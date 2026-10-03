"""Логика приложения без привязки к GUI.

Вся сетевая работа идёт в отдельном потоке со своим asyncio-циклом, а
наружу (в GUI) уходят события через потокобезопасную очередь — так окно
никогда не подвисает, и эту часть можно тестировать без tkinter.

События (кортежи в ``events``):
    ("log", str)
    ("status", str)
    ("progress", done: int, total: int)
    ("results", list[CheckResult])     — новый список рабочих прокси
    ("busy", bool)                      — идёт сбор/проверка
    ("vpn", "off" | "connecting" | "on")
    ("vpn_info", str, "ok" | "wait" | "warn")  — через какой прокси идём, сколько живых
    ("vpn_active", str | None, list[str])  — адрес прокси, через который идёт трафик, и вся группа VPN
    ("error", str)
    ("ask", str, holder)  — вопрос Да/Нет/Отмена; GUI кладёт ответ в holder["answer"] и делает holder["event"].set()
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import json
import logging
import queue
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from . import (app_routing, app_settings, checker, netpath, pipeline, scraper, singbox_config, singbox_manager,
               source_stats, storage)
from .reputation import Reputation
from .models import CheckResult

log = logging.getLogger("proxyparser")


class QueueLogHandler(logging.Handler):
    def __init__(self, events: "queue.Queue[tuple]"):
        super().__init__()
        self.events = events
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.events.put(("log", self.format(record)))
        except Exception:
            pass


class AppController:
    def __init__(self) -> None:
        self.events: "queue.Queue[tuple]" = queue.Queue()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True, name="net-loop")
        self._thread.start()

        self.results: list[CheckResult] = storage.load_working_proxies()
        self.busy = False
        self._singbox = singbox_manager.SingBoxProcess()
        self._vpn_state = "off"
        self._vpn_stop_requested = False
        self._vpn_generation = 0
        self._vpn_info_future: concurrent.futures.Future | None = None
        self._pending_asks: list[dict] = []
        self._last_retest = 0.0
        self._singbox_log = None
        self._singbox_seen: dict[str, float] = {}  # недавние ошибки sing-box — не повторять в журнале
        self.rep = Reputation.load()
        self.autoheal = True            # автоподбор замены, когда прокси в VPN умирают
        self.routing = app_routing.load()  # какие приложения идут через прокси
        self.settings = app_settings.load()
        self._current_group: list[str] = []
        self._pin_tag: str | None = None   # тег закреплённого прокси в текущем конфиге sing-box
        self._pin_dead_ticks = 0
        self._last_heal = 0.0
        self._heal_strikes = 0
        self._connect_after_refresh = False
        # когда список обновлялся в последний раз — для фонового обновления
        try:
            self._last_refresh_at = storage.WORKING_PROXIES_FILE.stat().st_mtime
        except OSError:
            self._last_refresh_at = 0.0

        handler = QueueLogHandler(self.events)
        root_logger = logging.getLogger("proxyparser")
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.INFO)
        self._submit(self._auto_refresh_loop())

    # ---------- утилиты ----------

    def _emit(self, *event: Any) -> None:
        self.events.put(event)

    def _submit(self, coro) -> concurrent.futures.Future:
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    @property
    def vpn_state(self) -> str:
        return self._vpn_state

    @property
    def last_refresh_at(self) -> float:
        """Когда список обновлялся в последний раз (0 — ни разу)."""
        return self._last_refresh_at

    def _set_vpn(self, state: str) -> None:
        prev = self._vpn_state
        self._vpn_state = state
        self._emit("vpn", state)
        if state == "on" and prev != "on":
            self._vpn_info_future = self._submit(self._vpn_info_loop())
        elif state != "on" and self._vpn_info_future is not None:
            self._vpn_info_future.cancel()
            self._vpn_info_future = None
            self._emit("vpn_info", "", "ok")
            self._emit("vpn_active", None, [])

    # ---------- сбор и проверка ----------

    def refresh(self, timeout: float = checker.DEFAULT_TIMEOUT_S, concurrency: int = checker.DEFAULT_CONCURRENCY,
                background: bool = False) -> None:
        """Обновить список. ``background`` — фоновое обновление по расписанию:
        без вопросов и окон с ошибками, и работающий VPN без нужды не
        перезапускается (перезапуск рвёт все соединения — звонки, загрузки)."""
        if self.busy:
            return
        self.busy = True
        self._emit("busy", True)
        self._submit(self._refresh(timeout, concurrency, background))

    AUTO_REFRESH_RETRY_S = 30 * 60  # фоновое обновление не удалось — повторить через полчаса

    def _auto_refresh_due(self, now: float) -> bool:
        hours = self.settings.auto_refresh_hours
        return bool(hours) and not self.busy and now - self._last_refresh_at >= hours * 3600

    async def _auto_refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                if self._auto_refresh_due(time.time()):
                    log.info("Фоновое обновление списка (раз в %d ч)...", self.settings.auto_refresh_hours)
                    self.refresh(background=True)
            except Exception:  # noqa: BLE001
                log.exception("Фоновое обновление не запустилось")

    def _retry_refresh_later(self) -> None:
        hours = self.settings.auto_refresh_hours or 1
        self._last_refresh_at = time.time() - hours * 3600 + self.AUTO_REFRESH_RETRY_S

    def startup(self) -> None:
        """Сразу после запуска окна: автоподключение VPN, если включено."""
        if not self.settings.auto_connect or self._vpn_state != "off":
            return
        if not singbox_manager.is_admin():
            log.warning("Автоподключение VPN пропущено: программа запущена без прав администратора")
            return
        if self.results:
            log.info("Автоподключение VPN...")
            self.connect_vpn()
        else:
            log.info("Список прокси пуст — сначала обновлю его, потом подключу VPN")
            self._connect_after_refresh = True
            self.refresh()

    async def _refresh(self, timeout: float, concurrency: int, background: bool = False) -> None:
        try:
            # 1) Сбор со всех источников из sources.json
            self._emit("status", "Собираю прокси из источников...")
            self._emit("progress", 0, 0)
            proxies, stats = await asyncio.to_thread(self._scrape_any_way)
            per = ", ".join(f"{k}: {v}" for k, v in stats.per_source.items())
            log.info("Собрано %d уникальных прокси (%s)", len(proxies), per)
            for name, err in stats.sources_failed.items():
                log.warning("Источник %s не открылся: %s", name, err)

            # 2) Проверять нужно с обычного подключения. Наш VPN выключать не
            #    нужно — трафик самой программы идёт мимо него (правило в
            #    конфиге sing-box), а вот сторонний VPN попросим выключить.
            #    В фоне не спрашиваем (человека может не быть у компьютера) —
            #    просто откладываем.
            if background:
                found = await asyncio.to_thread(netpath.detect_external_vpn)
                if found:
                    log.info("Фоновое обновление отложено: включён сторонний VPN (%s)", ", ".join(found))
                    self._retry_refresh_later()
                    self._emit("status", "Фоновое обновление отложено: включён сторонний VPN")
                    return
            elif not await self._ensure_no_external_vpn():
                self._emit("status", "Проверка отменена")
                return

            last = {"stage": None, "at": 0.0}

            def on_stage(name: str, done: int, total: int) -> None:
                # Колбэк зовётся на КАЖДЫЙ прокси (в больших списках — десятки
                # тысяч раз); окну хватает ~10 обновлений в секунду.
                now = time.monotonic()
                if name == last["stage"] and done < total and now - last["at"] < 0.1:
                    return
                last["stage"], last["at"] = name, now
                self._emit("progress", done, max(total, 1))
                self._emit("status", f"{name}: {done} из {total}..." if total else f"{name}...")

            results, ps = await pipeline.run(proxies, self.rep, timeout=timeout, concurrency=concurrency, on_stage=on_stage)
            await asyncio.to_thread(self.rep.save)

            log.info(
                "Кандидатов: %d из источников + %d проверенных ранее; пропущено по репутации: %d; "
                "лишних портов «ферм»: %d; из РФ: %d; мёртвых по быстрому отсеву: %d; "
                "полную проверку прошли %d из %d",
                ps.from_sources, ps.from_reputation, ps.skipped_by_reputation, ps.skipped_farms, ps.excluded_country,
                ps.prefilter_dead, ps.working, ps.full_checked,
            )
            fast = sorted((r.speed_kbps for r in results if r.working and r.speed_kbps), reverse=True)
            if fast:
                log.info("Скорость замерена у %d прокси, лучшие: %s КБ/с", ps.speed_measured,
                         ", ".join(f"{v:.0f}" for v in fast[:5]))
            for note in ps.notes:
                log.info(note)

            # статистика источников: откуда приходят хорошие прокси
            if stats.members:
                rows = source_stats.compute(stats.members, results)
                totals = await asyncio.to_thread(source_stats.save, rows)
                log.info("Статистика источников (этот запуск):")
                for line in source_stats.format_table(rows):
                    log.info("  %s", line)
                runs = max((t.get("runs", 0) for t in totals.values()), default=0)
                if runs > 1:
                    log.info("Итого быстрых рабочих за все запуски: %s",
                             ", ".join(f"{k}: {v.get('fast', 0)}" for k, v in
                                       sorted(totals.items(), key=lambda kv: -kv[1].get("fast", 0))))

            # исключённый вручную, пока шла проверка, в список не возвращается
            results = [r for r in results if not self.rep.is_banned(r.proxy)]
            storage.save_results(results)
            self.results = storage.sorted_by_priority(results)
            self._last_refresh_at = time.time()
            self._emit("results", self.results)
            self._emit("status", f"Готово: рабочих {len(self.results)} из {len(results)}")

            # 3) Если VPN включён — применяем новый список (перезапуск ~1 с).
            #    В фоне — только если текущие прокси сдают: иначе перезапуск
            #    оборвал бы звонки и загрузки без всякой пользы. Свежий список
            #    и так пойдёт в дело — при автоподборе и следующем подключении.
            if self._singbox.running and self.results:
                if background:
                    health = await asyncio.to_thread(fetch_group_health)
                    if health is not None and health[0] > health[2] // 2:
                        log.info("Список обновлён в фоне; VPN не перезапускаю — отвечают %d из %d прокси "
                                 "(новые пойдут в дело при автоподборе или следующем подключении)",
                                 health[0], health[2])
                        return
                log.info("Применяю обновлённый список к работающему VPN...")
                await asyncio.to_thread(self._restart_vpn_blocking)
            elif self._connect_after_refresh and self.results:
                self._connect_after_refresh = False
                log.info("Автоподключение VPN...")
                self.connect_vpn()
        except Exception as exc:  # noqa: BLE001 — всё показываем пользователю
            log.exception("Ошибка при обновлении списка")
            if background:
                self._retry_refresh_later()  # в фоне — без окна с ошибкой, повтор позже
            else:
                self._emit("error", f"Ошибка при обновлении списка: {exc}")
        finally:
            self._connect_after_refresh = False
            self.busy = False
            self._emit("busy", False)

    def _scrape_any_way(self):
        """Источники открываем напрямую; если какой-то не открылся, а
        сохранённые прокси есть — пробуем его через них."""
        # узлы — только через мост sing-box; для загрузки списков хватает обычных прокси
        plain = [r.proxy for r in self.results if not r.proxy.type.is_node]
        fallback = netpath.ProxyFetcher(plain) if plain else None
        proxies, stats = scraper.scrape(scraper.direct_fetcher(timeout_s=15), fallback_fetch=fallback)
        if not proxies:
            failed = "; ".join(f"{k}: {v}" for k, v in stats.sources_failed.items())
            raise RuntimeError(f"ни один источник не отдал прокси ({failed})")
        return proxies, stats

    async def _ensure_no_external_vpn(self) -> bool:
        while True:
            found = await asyncio.to_thread(netpath.detect_external_vpn)
            if not found:
                return True
            names = "\n".join(f"  • {n}" for n in found)
            answer = await self._ask(
                "Похоже, включён сторонний VPN:\n"
                f"{names}\n\n"
                "Через него проверка покажет, доступны ли прокси из страны того VPN, а не с твоего "
                "обычного подключения — и в нашем VPN большинство «рабочих» прокси не ответят.\n\n"
                "Выключи его и нажми «Да» (проверю ещё раз).\n"
                "«Нет» — проверять как есть.  «Отмена» — не проверять."
            )
            if answer is None:
                return False
            if answer is False:
                log.warning("Проверка идёт при включённом стороннем VPN — результаты могут не совпасть с реальностью")
                return True

    async def _ask(self, text: str) -> bool | None:
        """Задать вопрос пользователю через GUI и дождаться ответа (Да/Нет/Отмена)."""
        holder: dict = {"event": threading.Event(), "answer": None}
        self._pending_asks.append(holder)
        self._emit("ask", text, holder)
        await asyncio.to_thread(holder["event"].wait)
        self._pending_asks.remove(holder)
        return holder["answer"]

    # ---------- VPN (sing-box + TUN) ----------

    def connect_vpn(self) -> None:
        if self._vpn_state != "off":
            return
        self._set_vpn("connecting")
        self._submit(asyncio.to_thread(self._connect_vpn_flow))

    def _connect_vpn_flow(self) -> None:
        try:
            if not self.results:
                self._emit("error", "Нет рабочих прокси — сначала нажми «Обновить список»")
                self._set_vpn("off")
                return
            self._start_vpn_blocking()
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка запуска VPN")
            self._emit("error", f"Не удалось включить VPN: {exc}")
            self._set_vpn("off")

    def _start_vpn_blocking(self) -> None:
        self._set_vpn("connecting")
        exe = singbox_manager.find_singbox()
        if exe is None:
            exe = singbox_manager.download_singbox(log=log.info)
        meta = singbox_config.write_config(
            self.results, singbox_manager.CONFIG_PATH,
            bypass_process_paths=singbox_manager.own_process_paths(),
            routing=self.routing,
            pinned=self.settings.pinned_address,
            countries=self.settings.countries,
        )
        self._current_group = list(meta.get("chosen", []))
        self._pin_tag = meta.get("pin_tag")
        log.info(meta["comment_ru"])
        log.info("Запускаю sing-box: %s", exe)
        # сначала новое поколение, потом сброс флага: запоздалый выход
        # прежнего процесса уже не примут за неожиданное падение
        self._vpn_generation += 1
        gen = self._vpn_generation
        self._vpn_stop_requested = False
        self._open_singbox_log()
        self._singbox.start(
            exe,
            singbox_manager.CONFIG_PATH,
            self._on_singbox_line,
            lambda code: self._on_singbox_exit(code, gen),
        )

        def _fallback_mark_on() -> None:
            # если строки "started" в логе не было, но процесс жив — считаем подключённым
            if self._singbox.running and self._vpn_state == "connecting":
                self._set_vpn("on")
                self._emit("status", "VPN подключён")

        timer = threading.Timer(8.0, _fallback_mark_on)
        timer.daemon = True  # не задерживать закрытие программы
        timer.start()

    def _open_singbox_log(self) -> None:
        # полный лог sing-box в файл — пригодится для разбора проблем
        try:
            if self._singbox_log is not None:
                self._singbox_log.close()
            self._singbox_log = open(SINGBOX_LOG, "w", encoding="utf-8", buffering=1)
        except OSError:
            self._singbox_log = None

    def _on_singbox_line(self, line: str) -> None:
        if self._singbox_log is not None:
            try:
                self._singbox_log.write(line + "\n")
            except (OSError, ValueError):
                pass
        journal = singbox_journal_line(line, self._singbox_seen)
        if journal:
            self._emit("log", journal)
        if self._vpn_state == "connecting" and "started" in line.lower():
            self._set_vpn("on")
            self._emit("status", "VPN подключён")

    def _on_singbox_exit(self, code: int, gen: int) -> None:
        if gen != self._vpn_generation:
            return  # запоздалое событие от предыдущего (уже заменённого) процесса
        if not self._vpn_stop_requested:
            self._emit("error", f"sing-box завершился с кодом {code} — подробности в логе ниже")
        self._set_vpn("off")

    def _kill_singbox(self) -> None:
        """Остановить sing-box намеренно: его выход — не ошибка."""
        self._vpn_stop_requested = True
        self._vpn_generation += 1
        self._singbox.stop()

    def _restart_vpn_blocking(self) -> None:
        """Пересобрать конфиг из self.results и перезапустить sing-box."""
        self._kill_singbox()
        self._start_vpn_blocking()

    def disconnect_vpn(self) -> None:
        self._submit(asyncio.to_thread(self._stop_vpn_blocking))

    # ---------- настройки ----------

    def update_settings(self, settings: "app_settings.AppSettings") -> None:
        """Сохранить настройки. Если поменялись закреплённый прокси или страны,
        а VPN включён — применить сразу (перезапуск sing-box, около секунды)."""
        old = self.settings
        self.settings = settings
        try:
            app_settings.save(settings)
        except OSError as exc:
            self._emit("error", f"Не удалось сохранить настройки: {exc}")
        changed_vpn = (old.pinned_address != settings.pinned_address or old.countries != settings.countries)
        if changed_vpn and self._singbox.running and self.results:
            self._emit("status", "Применяю настройки...")
            self._submit(asyncio.to_thread(self._restart_vpn_safely))

    def pin_proxy(self, address: str | None) -> None:
        """Закрепить прокси для VPN (None — открепить, снова автовыбор)."""
        s = app_settings.from_dict(dataclasses.asdict(self.settings))
        if address is None:
            s.pinned = None
            log.info("Прокси откреплён — снова автовыбор лучшего")
        else:
            r = next((r for r in self.results if r.proxy.address == address), None)
            s.pinned = {"address": address, "type": r.proxy.type.value if r else ""}
            log.info("Закреплён прокси %s", address)
        self.update_settings(s)

    def ban_proxy(self, address: str) -> None:
        """Исключить прокси вручную (через него не открывается сайт, браузер
        ругается на сертификат…): больше не проверяется и не попадает в VPN.
        Если он сейчас в VPN — VPN перезапускается без него."""
        self._submit(self._ban(address))

    async def _ban(self, address: str) -> None:
        # в сетевом потоке: репутацию в это время может обновлять проверка
        r = next((r for r in self.results if r.proxy.address == address), None)
        if r is None:
            return
        self.rep.ban(r.proxy)
        self.results = [x for x in self.results if x is not r]
        log.info("Прокси %s исключён: больше не проверяется и не попадёт в VPN", address)
        self._emit("results", self.results)
        await asyncio.to_thread(self.rep.save)
        await asyncio.to_thread(storage.save_results, self.results)
        if self.settings.pinned_address == address:
            self.pin_proxy(None)  # открепление само перезапустит VPN
        elif address in self._current_group and self._singbox.running and self.results:
            self._emit("status", "Перезапускаю VPN без исключённого прокси...")
            await asyncio.to_thread(self._restart_vpn_safely)

    def _restart_vpn_safely(self) -> None:
        try:
            self._restart_vpn_blocking()
        except Exception as exc:  # noqa: BLE001
            log.exception("Не удалось перезапустить VPN")
            self._emit("error", f"Не удалось применить настройки: {exc}")
            self._set_vpn("off")

    # ---------- маршрутизация по приложениям ----------

    def set_routing(self, routing: "app_routing.RoutingSettings") -> None:
        """Сохранить настройки маршрутизации; если VPN включён — применить
        сразу (перезапуск sing-box, обрыв около секунды)."""
        if routing.to_dict() == self.routing.to_dict():
            return
        self.routing = routing
        try:
            app_routing.save(routing)
        except OSError as exc:
            self._emit("error", f"Не удалось сохранить настройки маршрутизации: {exc}")
        log.info("Маршрутизация: %s", routing.describe())
        if self._singbox.running and self.results:
            self._emit("status", "Применяю маршрутизацию...")
            self._submit(asyncio.to_thread(self._restart_vpn_safely))

    def _stop_vpn_blocking(self) -> None:
        self._kill_singbox()
        self._set_vpn("off")
        log.info("VPN отключён")

    # ---------- состояние VPN через Clash API sing-box ----------

    async def _vpn_info_loop(self) -> None:
        tick = 0
        while True:
            tick += 1
            if self.autoheal and tick % 15 == 0:  # примерно раз в минуту
                try:
                    await self._maybe_heal()
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001
                    log.exception("Автоподбор прокси не удался")
            try:
                if self._pin_tag:
                    await self._pin_failover()
                text, level, current_dead, active = await asyncio.to_thread(fetch_vpn_status)
                self._emit("vpn_info", text, level)
                self._emit("vpn_active", active, list(self._current_group))
                # sing-box сам перепроверяет прокси только по таймеру; если выбранный
                # уже не отвечает, а другие живы — просим перепроверить сразу
                if current_dead and time.monotonic() - self._last_retest > 20:
                    self._last_retest = time.monotonic()
                    log.info("Текущий прокси не отвечает — прошу sing-box выбрать другой")
                    await asyncio.to_thread(force_retest)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._emit("vpn_info", "Жду ответа от sing-box...", "wait")
            await asyncio.sleep(4)

    PIN_DEAD_TICKS = 2  # столько проверок подряд (по 4 с) закреплённый должен быть мёртв

    async def _pin_failover(self) -> None:
        """Закреплённый прокси умер — временно автовыбор; ожил — обратно на него."""
        state = await asyncio.to_thread(pin_state, self._pin_tag)
        if state is None:
            return
        pin_alive, active = state
        addr = _tag_to_address(self._pin_tag)
        if pin_alive is False and active:
            self._pin_dead_ticks += 1
            if self._pin_dead_ticks >= self.PIN_DEAD_TICKS:
                await asyncio.to_thread(_clash_select, singbox_config.PIN_SELECTOR_TAG, singbox_config.URLTEST_TAG)
                log.info("Закреплённый прокси %s не отвечает — временно автовыбор лучшего", addr)
                self._pin_dead_ticks = 0
            return
        self._pin_dead_ticks = 0
        if pin_alive and not active:
            await asyncio.to_thread(_clash_select, singbox_config.PIN_SELECTOR_TAG, self._pin_tag)
            log.info("Закреплённый прокси %s снова отвечает — возвращаюсь на него", addr)

    # ---------- автоподбор: замена умерших прокси на ходу ----------

    HEAL_MIN_INTERVAL = 5 * 60
    HEAL_RESERVE_CHECK = 30

    async def _maybe_heal(self) -> None:
        if self.busy or not self._singbox.running:
            return
        health = await asyncio.to_thread(fetch_group_health)
        if health is None:
            return
        alive, tested, total = health
        degraded = tested == total and total > 0 and alive <= max(1, total // 4)
        self._heal_strikes = self._heal_strikes + 1 if degraded else 0
        if self._heal_strikes < 2 or time.monotonic() - self._last_heal < self.HEAL_MIN_INTERVAL:
            return
        self._last_heal = time.monotonic()
        self._heal_strikes = 0
        log.info("В VPN отвечают только %d из %d прокси — подбираю замену из запаса...", alive, total)

        current = set(self._current_group)
        # замеренно медленные в запас не идут вовсе — их и проверять незачем
        reserve = [r for r in self.results if r.working and r.proxy.address not in current
                   and not singbox_config.is_slow(r)
                   and singbox_config.country_allowed(r, self.settings.countries)]
        # нестабильные по истории — в конец очереди
        reserve.sort(key=lambda r: (singbox_config.is_unstable(r), singbox_config._rank(r)))  # noqa: SLF001
        reserve = reserve[: self.HEAL_RESERVE_CHECK]
        fresh: list[CheckResult] = []
        if reserve:
            fresh = await checker.check_all([r.proxy for r in reserve])
            # скорость перемеряем у всех живых: за время работы VPN она могла упасть
            await checker.measure_top_speeds(fresh, top=len(fresh))
            self.rep.update(fresh)
            await asyncio.to_thread(self.rep.save)
        # замена засчитывается, только если у прокси ДОКАЗАНА нормальная скорость
        good = [r for r in fresh if r.working and singbox_config.is_fast_enough(r)]
        if len(good) >= singbox_config.MIN_PROXIES:
            # свежие результаты запаса + отказавшие из текущей группы помечаем нерабочими
            by_addr = {r.proxy.address: r for r in self.results}
            for r in fresh:
                by_addr[r.proxy.address] = r
            for addr in current:
                if addr in by_addr:
                    by_addr[addr].working = False
            self.results = storage.sorted_by_priority(list(by_addr.values()))
            storage.save_results(list(by_addr.values()))
            self._emit("results", self.results)
            log.info("Нашёл %d живых прокси в запасе со скоростью от %d КБ/с — перезапускаю VPN с ними",
                     len(good), singbox_config.MIN_SPEED_KBPS)
            await asyncio.to_thread(self._restart_vpn_blocking)
        else:
            log.info("В запасе почти нет живых и быстрых прокси — запускаю полное обновление списка")
            self.refresh()

    # ---------- завершение ----------

    def shutdown(self) -> None:
        for holder in list(self._pending_asks):
            holder["event"].set()
        self._kill_singbox()
        if self._singbox_log is not None:
            try:
                self._singbox_log.close()
            except OSError:
                pass
            self._singbox_log = None
        def _stop_loop() -> None:
            # сначала отменить фоновые задачи (автообновление, статус VPN),
            # потом остановить цикл — чтобы выход был чистым
            for task in asyncio.all_tasks(self._loop):
                task.cancel()
            self._loop.call_soon(self._loop.stop)

        self._loop.call_soon_threadsafe(_stop_loop)


SINGBOX_LOG = singbox_manager.VPN_DIR / "sing-box.log"


def _tag_to_address(tag: str) -> str:
    # формат тега: proxy-<i>-<host_с_подчёркиваниями>-<port>; в домене узла
    # бывают дефисы — поэтому номер отрезается слева, порт — справа
    parts = tag.split("-", 2)
    if len(parts) == 3 and parts[0] == "proxy" and "-" in parts[2]:
        host, port = parts[2].rsplit("-", 1)
        return f"{host.replace('_', '.')}:{port}"
    return tag


def _api_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def force_retest(api_addr: str | None = None) -> None:
    """Попросить sing-box немедленно перепроверить все прокси группы (Clash API)."""
    api_addr = api_addr or singbox_config.CLASH_API_ADDR
    query = urllib.parse.urlencode({"url": singbox_config.URLTEST_URL, "timeout": 5000})
    try:
        with _api_opener().open(f"http://{api_addr}/group/{singbox_config.URLTEST_TAG}/delay?{query}", timeout=15):
            pass
    except Exception as exc:  # noqa: BLE001
        log.debug("Перепроверка через Clash API не удалась: %s", exc)


def fetch_group_health(api_addr: str | None = None) -> tuple[int, int, int] | None:
    """(живых, проверено, всего) в основной группе VPN; None — API недоступен."""
    api_addr = api_addr or singbox_config.CLASH_API_ADDR
    try:
        with _api_opener().open(f"http://{api_addr}/proxies", timeout=3) as resp:
            data = json.load(resp)
    except Exception:  # noqa: BLE001
        return None
    proxies = data.get("proxies", {})
    members = proxies.get(singbox_config.URLTEST_TAG, {}).get("all", [])
    alive = tested = 0
    for tag in members:
        hist = proxies.get(tag, {}).get("history") or []
        if hist:
            tested += 1
            alive += hist[-1].get("delay", 0) > 0
    return alive, tested, len(members)


def fetch_vpn_status(api_addr: str | None = None) -> tuple[str, str, bool, str | None]:
    """Спросить у sing-box (Clash API), какой прокси сейчас выбран и сколько
    прокси в группе реально отвечают. Возвращает (текст, уровень, выбранный
    не отвечает, адрес прокси, через который идёт трафик)."""
    api_addr = api_addr or singbox_config.CLASH_API_ADDR
    with _api_opener().open(f"http://{api_addr}/proxies", timeout=3) as resp:
        data = json.load(resp)
    proxies = data.get("proxies", {})
    group = proxies.get(singbox_config.URLTEST_TAG, {})
    members = group.get("all", [])
    total = len(members)

    def last_delay(tag: str) -> int | None:
        hist = proxies.get(tag, {}).get("history") or []
        return hist[-1].get("delay", 0) if hist else None

    delays = {tag: last_delay(tag) for tag in members}
    tested = [d for d in delays.values() if d is not None]
    alive = sum(1 for d in tested if d > 0)

    if not tested:
        return f"Проверяю прокси... (0 из {total})", "wait", False, None
    if alive == 0:
        if len(tested) < total:
            return f"Проверяю прокси... ({len(tested)} из {total}, пока ни один не ответил)", "wait", False, None
        return f"Ни один из {total} прокси сейчас не отвечает — нажми «Обновить список»", "warn", False, None
    now = group.get("now", "")
    active = _tag_to_address(now) if now else None
    now_delay = delays.get(now)
    delay_txt = f"{now_delay} мс" if now_delay else "—"
    current_dead = not now_delay  # выбранный прокси не ответил на последней проверке
    level = "wait" if current_dead else "ok"
    via = f"Через {_tag_to_address(now)} ({delay_txt})"
    selector = proxies.get(singbox_config.PIN_SELECTOR_TAG)
    if selector:
        pin_tag = (selector.get("all") or [""])[0]
        if selector.get("now") == pin_tag:
            active = _tag_to_address(pin_tag)
            pin_delay = last_delay(pin_tag)
            via = f"Через закреплённый {_tag_to_address(pin_tag)} ({f'{pin_delay} мс' if pin_delay else '—'})"
            current_dead, level = False, "ok" if pin_delay else "wait"
        else:
            via = f"Закреплённый {_tag_to_address(pin_tag)} не отвечает · {via[0].lower()}{via[1:]}"
            level = "wait"
    udp_group = proxies.get(singbox_config.UDP_URLTEST_TAG)
    if udp_group:
        udp_members = udp_group.get("all", [])
        udp_alive = sum(1 for t in udp_members if (last_delay(t) or 0) > 0)
        udp_txt = f" · UDP (звонки): через узлы, отвечают {udp_alive} из {len(udp_members)}"
    else:
        udp_txt = " · голос Discord: напрямую"
    return f"{via} · отвечают {alive} из {total}{udp_txt}", level, current_dead, active


SINGBOX_REPEAT_S = 60  # одну и ту же ошибку sing-box показываем в журнале не чаще раза в минуту
_SINGBOX_LINE = re.compile(r"^[+-]\d{4} \d{4}-\d\d-\d\d (\d\d:\d\d:\d\d) (\w+) (?:\[\d+ [^\]]*\] )?(.*)$")


def singbox_journal_line(line: str, seen: dict[str, float], now: float | None = None) -> str | None:
    """Строка лога sing-box для журнала в окне — или None, если она там не нужна.

    sing-box пишет строку на каждое соединение и DNS-запрос (тысячи за час) —
    в окно идут только запуск, предупреждения и ошибки. Ошибка соединения
    пишется дважды (группой и самим соединением) — остаётся одна, и одна и та
    же не чаще раза в минуту. Полный лог — в vpn/sing-box.log."""
    m = _SINGBOX_LINE.match(line.strip())
    if m is None:
        return f"sing-box: {line.strip()}" if line.strip() else None  # не формат лога — например, паника
    clock, level, text = m.groups()
    if level in ("INFO", "DEBUG", "TRACE"):
        return f"{clock}  sing-box запущен" if text.startswith("sing-box started") else None
    if level == "ERROR" and text.startswith("connection: "):
        return None
    now = time.monotonic() if now is None else now
    if now - seen.get(text, -SINGBOX_REPEAT_S) < SINGBOX_REPEAT_S:
        return None
    seen[text] = now
    if len(seen) > 200:
        seen.clear()
    label = "ВНИМАНИЕ" if level == "WARN" else "ОШИБКА"
    return f"{clock}  sing-box {label}: {text}"


def _clash_select(group: str, name: str, api_addr: str | None = None) -> None:
    """Выбрать outbound в группе-переключателе (selector) через Clash API."""
    api_addr = api_addr or singbox_config.CLASH_API_ADDR
    req = urllib.request.Request(
        f"http://{api_addr}/proxies/{urllib.parse.quote(group)}",
        data=json.dumps({"name": name}).encode(), method="PUT", headers={"Content-Type": "application/json"},
    )
    with _api_opener().open(req, timeout=3):
        pass


def pin_state(pin_tag: str, api_addr: str | None = None) -> tuple[bool | None, bool] | None:
    """(жив ли закреплённый, выбран ли он сейчас) — или None, если API или
    переключателя нет. «Жив» = None, пока группа ещё не проверялась (старт);
    False — другие прокси уже проверены, а у закреплённого успешной проверки
    нет (неудачная проверка в sing-box стирает историю)."""
    try:
        with _api_opener().open(f"http://{api_addr or singbox_config.CLASH_API_ADDR}/proxies", timeout=3) as resp:
            proxies = json.load(resp).get("proxies", {})
    except Exception:  # noqa: BLE001
        return None
    selector = proxies.get(singbox_config.PIN_SELECTOR_TAG)
    if not selector:
        return None

    def alive(tag: str) -> bool | None:
        hist = proxies.get(tag, {}).get("history") or []
        return (hist[-1].get("delay", 0) > 0) if hist else None

    pin_alive = alive(pin_tag)
    if pin_alive is None:
        members = proxies.get(singbox_config.URLTEST_TAG, {}).get("all", [])
        tested_others = any(alive(t) is not None for t in members if t != pin_tag)
        pin_alive = False if tested_others else None
    return pin_alive, selector.get("now") == pin_tag

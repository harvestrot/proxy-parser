"""Лёгкий локальный SOCKS5-сервер с автоматическим переключением прокси.

Режим «без прав администратора»: поднимается на 127.0.0.1:<port>,
прописывается как SOCKS5-прокси в браузере/приложении, а дальше сам
выбирает рабочий внешний прокси (лучший по скорости и стабильности) и при обрыве
переключается на следующий — для одного конкретного приложения это
ощущается как «всегда работающее» подключение, аналог VPN на уровне
приложения (но не всей системы — для системного уровня см. vpn/ и
TUN-режим через sing-box).
"""
from __future__ import annotations

import asyncio
import logging
import socket as socket_mod
import struct
import time

from .checker import check_all
from .models import CheckResult, Proxy
from .singbox_config import best_first
from .upstream import UpstreamError, connect_via

log = logging.getLogger(__name__)

DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 1080
DEFAULT_CONNECT_TIMEOUT = 6.0
DEFAULT_REVALIDATE_INTERVAL_S = 5 * 60


class ProxyPool:
    """Потокобезопасный (в рамках одного event loop) пул рабочих прокси.
    Порядок — тот же фильтр, что и у VPN: скорость и стабильность, а не
    только тип и пинг."""

    def __init__(self, results: list[CheckResult], pinned: str | None = None):
        self._pinned = pinned
        self._results = self._order(results)
        self._dead: set[tuple[str, int]] = set()

    def _order(self, results: list[CheckResult]) -> list[CheckResult]:
        ordered = best_first(results)
        if self._pinned:  # закреплённый — первым, остальные — запасом при его отказе
            ordered.sort(key=lambda r: r.proxy.address != self._pinned)
        return ordered

    def candidates(self) -> list[Proxy]:
        alive = [r.proxy for r in self._results if (r.proxy.host, r.proxy.port) not in self._dead]
        if not alive and self._dead:
            # все разом «умерли» — чаще всего это короткий сбой сети у нас, а не
            # у прокси: даём всем ещё шанс, а не отказываем до перепроверки
            log.info("Все прокси пула помечены нерабочими — пробую их заново")
            self._dead.clear()
            alive = [r.proxy for r in self._results]
        return alive

    def mark_dead(self, proxy: Proxy) -> None:
        self._dead.add((proxy.host, proxy.port))

    def replace(self, results: list[CheckResult]) -> None:
        self._results = self._order(results)
        self._dead.clear()

    def stats(self) -> str:
        alive = sum(1 for r in self._results if (r.proxy.host, r.proxy.port) not in self._dead)
        return f"{alive}/{len(self._results)} прокси живы"


async def _revalidate_loop(pool: ProxyPool, interval_s: float) -> None:
    while True:
        await asyncio.sleep(interval_s)
        old = {r.proxy.address: r for r in pool._results}  # noqa: SLF001 — внутренний модуль
        if not old:
            continue
        log.info("Перепроверка пула (%d прокси)...", len(old))
        # UDP браузеру не нужен — не тратим на него время
        results = await check_all([r.proxy for r in old.values()], check_udp_support=False)
        for r in results:
            # скорость и историю переносим из прошлой проверки: заново качать
            # файл через каждый прокси раз в 5 минут — слишком много трафика
            prev = old.get(r.proxy.address)
            if prev is not None:
                r.speed_kbps, r.rep_ok, r.rep_checks = prev.speed_kbps, prev.rep_ok, prev.rep_checks
        pool.replace(results)
        log.info("Перепроверка завершена: %s", pool.stats())


async def _relay(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (OSError, asyncio.IncompleteReadError):  # в т.ч. ConnectionAbortedError на Windows
        pass
    finally:
        dst.close()


async def _read_socks5_greeting(reader: asyncio.StreamReader) -> None:
    """Дочитать остаток приветствия (NMETHODS + METHODS); VER уже прочитан вызывающим кодом."""
    nmethods = (await reader.readexactly(1))[0]
    await reader.readexactly(nmethods)


async def _read_socks5_connect_request(reader: asyncio.StreamReader) -> tuple[str, int]:
    """Прочитать CONNECT-запрос клиента. Вызывать ТОЛЬКО после того, как
    серверный ответ на приветствие (метод аутентификации) уже отправлен —
    иначе конформный клиент будет ждать этот ответ и всё зависнет."""
    head = await reader.readexactly(4)
    if head[0] != 0x05:
        raise ValueError("не SOCKS5 клиент")
    atyp = head[3]
    if atyp == 0x01:
        host = socket_mod.inet_ntoa(await reader.readexactly(4))
    elif atyp == 0x03:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode("ascii", errors="ignore")
    elif atyp == 0x04:
        host = socket_mod.inet_ntop(socket_mod.AF_INET6, await reader.readexactly(16))
    else:
        raise ValueError(f"неизвестный ATYP={atyp}")
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    return host, port


async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, pool: ProxyPool, connect_timeout: float) -> None:
    peer = writer.get_extra_info("peername")
    try:
        ver = (await reader.readexactly(1))[0]
        if ver != 0x05:
            writer.close()
            return
        await _read_socks5_greeting(reader)

        # отвечаем клиенту, что аутентификация не требуется, ДО того как
        # он пришлёт CONNECT-запрос — так того и ждёт конформный клиент
        writer.write(b"\x05\x00")
        await writer.drain()

        dst_host, dst_port = await _read_socks5_connect_request(reader)
    except (asyncio.IncompleteReadError, ValueError, OSError):
        writer.close()
        return

    candidates = pool.candidates()
    if not candidates:
        log.warning("Нет живых прокси в пуле — запрос от %s к %s:%s отклонён", peer, dst_host, dst_port)
        try:
            await _reply_client(writer, 0x01)  # general failure
        except OSError:
            pass
        writer.close()
        return

    for proxy in candidates:
        try:
            start = time.monotonic()
            up_reader, up_writer = await connect_via(proxy, dst_host, dst_port, connect_timeout)
        except (UpstreamError, OSError, asyncio.TimeoutError) as exc:
            log.warning("Прокси %s не сработал для %s:%s (%s) — пробую следующий", proxy.address, dst_host, dst_port, exc)
            pool.mark_dead(proxy)
            continue
        elapsed = (time.monotonic() - start) * 1000
        log.info("%s:%s -> %s %s (%.0f мс)", dst_host, dst_port, proxy.type.value, proxy.address, elapsed)
        # Туннель есть — дальше только ретрансляция. Ошибки здесь уже не
        # повод пробовать следующий прокси: клиенту ответ «успех» отправлен.
        try:
            await _reply_client(writer, 0x00)
        except OSError:
            up_writer.close()
            writer.close()
            return
        await asyncio.gather(_relay(reader, up_writer), _relay(up_reader, writer))
        return

    log.error("Все прокси в пуле не сработали для %s:%s", dst_host, dst_port)
    try:
        await _reply_client(writer, 0x01)
    except OSError:
        pass
    writer.close()


async def _reply_client(writer: asyncio.StreamWriter, rep_code: int) -> None:
    # Упрощённый ответ: всегда сообщаем bind-адрес 0.0.0.0:0 — клиентам
    # это обычно не важно для исходящего CONNECT.
    writer.write(bytes([0x05, rep_code, 0x00, 0x01]) + b"\x00\x00\x00\x00" + b"\x00\x00")
    await writer.drain()


async def serve(
    results: list[CheckResult],
    *,
    host: str = DEFAULT_LISTEN_HOST,
    port: int = DEFAULT_LISTEN_PORT,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    revalidate_interval_s: float = DEFAULT_REVALIDATE_INTERVAL_S,
    pinned: str | None = None,
) -> None:
    pool = ProxyPool(results, pinned=pinned)
    log.info("Стартовал локальный SOCKS5-роутер на %s:%s (%s)", host, port, pool.stats())

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _accept(reader, writer, pool, connect_timeout)

    server = await asyncio.start_server(on_client, host, port)
    revalidate_task = asyncio.create_task(_revalidate_loop(pool, revalidate_interval_s))
    try:
        async with server:
            await server.serve_forever()
    finally:
        revalidate_task.cancel()

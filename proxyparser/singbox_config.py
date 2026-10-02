"""Генерация конфига sing-box для полноценного VPN-режима (TUN-интерфейс).

Идея: не изобретаем собственный TUN-стек (это отдельный большой пласт
работы, завязанный на драйверы и права администратора), а используем
зрелый открытый проект sing-box — он умеет:

  * поднять TUN-интерфейс (Wintun на Windows) и завернуть в него весь
    системный трафик (``tun`` inbound, ``auto_route``);
  * подключаться к обычным SOCKS4/SOCKS5/HTTP прокси как к upstream
    (``socks``/``http`` outbound);
  * автоматически выбирать живой/быстрый upstream и переключаться при
    обрыве (``urltest`` outbound-группа — это и есть автофейловер).

Мы только генерируем конфиг из списка рабочих прокси (см. pick_proxies: на
первом месте реальная скорость и стабильность по истории, медленные
отбрасываются). UDP (голос) идёт отдельной группой из прокси, у которых он
реально проходит. Группы sing-box сам перепроверяет по таймеру и выбирает
лучший живой.
"""
from __future__ import annotations

import json
import pathlib

from . import geo, storage
from .app_routing import MODE_EXCEPT, MODE_ONLY, RoutingSettings
from .models import CheckResult, ProxyType

TUN_INTERFACE_NAME = "sing-tun"
TUN_ADDRESS = "172.19.0.1/30"
TUN_ADDRESS_V6 = "fdfe:dcba:9876::1/126"  # чтобы IPv6-трафик не утекал мимо туннеля
URLTEST_TAG = "auto"
PIN_SELECTOR_TAG = "pinned"  # переключатель «закреплённый прокси / автовыбор»
URLTEST_URL = "https://www.gstatic.com/generate_204"
URLTEST_INTERVAL = "30s"  # бесплатные прокси отваливаются часто — проверяем чаще
CLASH_API_ADDR = "127.0.0.1:9090"  # GUI читает отсюда, какой прокси выбран и кто жив
DNS_BOOTSTRAP_SERVER = "1.1.1.1"

# Порядок приоритета, как просил пользователь: SOCKS5 -> SOCKS4 -> HTTPS.
_TIER_ORDER = (ProxyType.SOCKS5, ProxyType.SOCKS4, ProxyType.HTTPS)


FAST_LATENCY_MS = 2500  # медленнее этого прокси в VPN почти бесполезен
MIN_PROXIES = 3          # меньше — слишком хрупко, добираем из следующего типа
GOOD_SPEED_KBPS = 500    # замеренная скорость, с которой прокси считаем «хорошим» (~4 Мбит/с)
MIN_SPEED_KBPS = 150     # жёсткий порог: медленнее по замеру — в VPN не берём никогда,
                         # пока есть хоть кто-то не хуже (0 — прокси не отдал данные вовсе)
CONNECT_TIMEOUT = "5s"   # быстрее понимаем, что прокси умер (по умолчанию дольше)

# Стабильность по истории (репутации): прокси, который проверяли не меньше
# STABILITY_MIN_CHECKS раз и который прошёл меньше 60% проверок, —
# «нестабильный» (на практике такой при подключении VPN выбирался по пингу и
# первую минуту всё грузилось плохо, пока sing-box не уходил с него).
STABILITY_MIN_CHECKS = 4
STABILITY_MIN_SUCCESS = 0.6

# Допуск urltest основной группы. sing-box выбирает прокси по пингу одной
# проверки, но при разнице меньше допуска остаётся на текущем, а при выборе
# из равных берёт того, кто выше в списке, — а список упорядочен нашим
# рейтингом (скорость × стабильность × география). Большой допуск = sing-box
# держится за лучший по рейтингу прокси и уходит с него, только если тот
# умер или стал на секунду медленнее альтернативы, а не из-за случайного
# «шума» в пинге (на старте первые замеры особенно шумные).
URLTEST_TOLERANCE_MS = 1000

# UDP (голос Discord и т.п.) — отдельная группа из SOCKS5, у которых UDP
# реально проходит (серия пакетов, а не один).
UDP_URLTEST_TAG = "auto-udp"
MAX_UDP_PROXIES = 8
UDP_MIN_SPEED_KBPS = 30  # голосу много не надо, но прокси на 2–3 КБ/с ещё и теряет пакеты

# Процессы Discord: если прокси с UDP не нашлось, их UDP (голос) пускаем
# напрямую — иначе звонки не работают вовсе.
DISCORD_PROCESSES = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"]


def _latency(r: CheckResult) -> float:
    return r.latency_ms if r.latency_ms is not None else float("inf")


# При прочих равных SOCKS5 впереди (как просили), но быстрый HTTPS не теряется.
TYPE_FACTOR = {ProxyType.SOCKS5: 1.0, ProxyType.SOCKS4: 0.85, ProxyType.HTTPS: 0.85}


def score(r: CheckResult) -> float:
    """Общая «ценность» прокси: реальная скорость × надёжность по истории ×
    география × тип. Надёжность 0.5 (новичок) даёт множитель 1.0, проверенный
    многократно (≈1.0) — 1.5, часто падающий (≈0.2) — 0.7."""
    speed = r.speed_kbps or 0.0
    return (speed * (0.5 + r.reliability) * geo.geo_factor(r.proxy.country_code)
            * TYPE_FACTOR.get(r.proxy.type, 1.0))


def _rank(r: CheckResult) -> tuple:
    """Сначала прокси с хорошей замеренной скоростью (по общей ценности),
    потом остальные — по надёжности/географии и задержке."""
    speed = r.speed_kbps or 0.0
    bonus = (0.5 + r.reliability) * geo.geo_factor(r.proxy.country_code)
    return (0 if speed >= GOOD_SPEED_KBPS else 1, -score(r), -bonus, _latency(r))


MAX_PER_SUBNET = 2  # не больше стольких прокси из одной подсети /24 в группе VPN


def subnet(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else host


def diversify(ranked: list[CheckResult], limit: int = MAX_PER_SUBNET) -> list[CheckResult]:
    """Оставить порядок, но не больше ``limit`` прокси из одной подсети /24.

    Бесплатные прокси часто идут «фермами»: один оператор держит десятки
    портов на нескольких соседних IP. Если группа VPN целиком из такой фермы —
    упадёт разом и весь трафик видит один человек. Если после ограничения
    прокси остаётся меньше MIN_PROXIES — добираем отброшенными (лучше
    однообразная группа, чем никакой)."""
    taken: dict[str, int] = {}
    kept, spare = [], []
    for r in ranked:
        net = subnet(r.proxy.host)
        if taken.get(net, 0) < limit:
            taken[net] = taken.get(net, 0) + 1
            kept.append(r)
        else:
            spare.append(r)
    if len(kept) < MIN_PROXIES:
        kept += spare[: MIN_PROXIES - len(kept)]
    return kept


def is_slow(r: CheckResult) -> bool:
    """Скорость замерена и ниже порога (в т.ч. 0 — данные не пошли)."""
    return r.speed_kbps is not None and r.speed_kbps < MIN_SPEED_KBPS


def is_fast_enough(r: CheckResult) -> bool:
    """Скорость замерена и не ниже порога — годится для VPN без оговорок."""
    return r.speed_kbps is not None and r.speed_kbps >= MIN_SPEED_KBPS


def is_unstable(r: CheckResult) -> bool:
    """По истории прошёл меньше 60% проверок (и истории достаточно, чтобы судить)."""
    return r.rep_checks >= STABILITY_MIN_CHECKS and r.rep_ok / r.rep_checks < STABILITY_MIN_SUCCESS


def _types_used(chosen: list[CheckResult]) -> list[ProxyType]:
    present = {r.proxy.type for r in chosen}
    return [t for t in _TIER_ORDER if t in present]


def pick_proxies(results: list[CheckResult], max_proxies: int = 15) -> tuple[list[CheckResult], list[ProxyType]]:
    """Выбрать прокси для основной (TCP) группы VPN.

    1. Есть прокси с хорошей ЗАМЕРЕННОЙ скоростью и нормальной задержкой —
       группа из них. Тип тут почти не важен: для обычного трафика
       HTTPS-прокси (CONNECT) ничем не хуже SOCKS5, а UDP идёт отдельной
       группой. Поэтому быстрый HTTPS не теряется из-за медленных SOCKS5;
       SOCKS5 остаётся первым при прочих равных.
    2. Таких меньше MIN_PROXIES — добираем до MIN_PROXIES следующими по
       «ценности» (с нормальной задержкой), а не размываем группу до 15.
    3. Скорость не замерялась вовсе — по приоритету SOCKS5 -> SOCKS4 -> HTTPS
       и задержке.
    """
    # sing-box внутри группы выбирает прокси по задержке, а не по скорости:
    # прокси с пингом 400 мс и скоростью 90 КБ/с он предпочтёт прокси с
    # пингом 450 мс и 5 МБ/с. Поэтому если прокси с хорошей ЗАМЕРЕННОЙ
    # скоростью хватает — в группу кладём только их.
    # Но и задержка важна: каждое новое соединение (а у страницы их десятки)
    # через прокси с откликом 6 с открывается 6 с, какая бы ни была скорость.
    # Замеренно медленные (ниже MIN_SPEED_KBPS) не берём вовсе, пока есть
    # хоть кто-то не хуже. Раньше при нехватке хороших группа «добиралась»
    # и ими — отсюда медленные прокси при автоподборе.
    working = [r for r in results if r.working]
    not_slow = [r for r in working if not is_slow(r)]
    usable = [r for r in not_slow if _latency(r) <= FAST_LATENCY_MS]
    stable = [r for r in usable if not is_unstable(r)]
    shaky = [r for r in usable if is_unstable(r)]
    good = [r for r in stable if r.speed_kbps is not None and r.speed_kbps >= GOOD_SPEED_KBPS]
    fair = [r for r in stable if r.speed_kbps is not None and MIN_SPEED_KBPS <= r.speed_kbps < GOOD_SPEED_KBPS]
    unknown = [r for r in stable if r.speed_kbps is None]
    primary = good or fair
    if primary:
        # Группа — из «основных» (хорошие, а если их нет — приемлемые по
        # скорости); если их меньше MIN_PROXIES, добираем только до минимума:
        # сначала приемлемыми, потом незамеренными и лишь в самом конце —
        # нестабильными по истории. Ограничение «не больше двух из одной /24»
        # действует на весь порядок сразу.
        ordered = (sorted(good, key=_rank) + sorted(fair, key=_rank) + sorted(unknown, key=_rank)
                   + sorted(shaky, key=_rank))
        kept = diversify(ordered)
        primary_ids = {id(r) for r in primary}
        chosen = [r for r in kept if id(r) in primary_ids]
        chosen_ids = {id(r) for r in chosen}
        for r in kept:
            if len(chosen) >= MIN_PROXIES:
                break
            if id(r) not in chosen_ids:
                chosen.append(r)
        chosen = chosen[:max_proxies]
        return chosen, _types_used(chosen)

    # Скорость не замерена ни у кого из подходящих — по приоритету типов и
    # задержке; замеренно медленные — только если больше совсем некого.
    return _pick_by_tiers(not_slow or working, max_proxies, lambda r: _latency(r) <= FAST_LATENCY_MS)


def country_allowed(r: CheckResult, countries: list[str] | set[str] | None) -> bool:
    return not countries or (r.proxy.country_code or "").upper() in countries


def filter_countries(results: list[CheckResult], countries: list[str] | None) -> tuple[list[CheckResult], bool]:
    """Оставить прокси из разрешённых стран. Возвращает (прокси, фильтр_сработал).
    Если в этих странах рабочих нет вовсе — все прокси (VPN лучше, чем никакого)
    и False: об этом надо предупредить."""
    if not countries:
        return results, True
    allowed = {c.upper() for c in countries}
    kept = [r for r in results if country_allowed(r, allowed)]
    if any(r.working for r in kept):
        return kept, True
    return results, False


def best_first(results: list[CheckResult]) -> list[CheckResult]:
    """Все рабочие прокси в порядке «от лучшего»: сначала те, кого фильтр
    берёт в группу VPN, потом остальные — медленные и нестабильные в конце.
    Для лёгкого режима, где прокси перебираются по очереди."""
    chosen, _ = pick_proxies(results, max_proxies=len(results))
    ids = {id(r) for r in chosen}
    rest = sorted((r for r in results if r.working and id(r) not in ids),
                  key=lambda r: (is_slow(r), is_unstable(r), _rank(r)))
    return chosen + rest


def _pick_by_tiers(working: list[CheckResult], max_proxies: int, is_fast) -> tuple[list[CheckResult], list[ProxyType]]:
    chosen: list[CheckResult] = []
    used: list[ProxyType] = []
    for ptype in _TIER_ORDER:
        fast = diversify(sorted((r for r in working if r.proxy.type == ptype and is_fast(r)), key=_rank))
        if fast:
            chosen += fast
            used.append(ptype)
        if len(chosen) >= MIN_PROXIES:
            break
    if not chosen:
        for ptype in _TIER_ORDER:
            tier = diversify(sorted((r for r in working if r.proxy.type == ptype), key=_rank))
            if tier:
                chosen, used = tier, [ptype]
                break
    return chosen[:max_proxies], used


UDP_MAX_TCP_LATENCY_MS = 4000  # UDP через SOCKS5 начинается с TCP-рукопожатия; sing-box ждёт его 5 с


def pick_udp_proxies(results: list[CheckResult], limit: int = MAX_UDP_PROXIES) -> list[CheckResult]:
    """Прокси, через которые реально проходит UDP (голос), — по задержке UDP,
    стабильные по истории впереди. Не берём:
      * прокси, до которых TCP-рукопожатие дольше ~4 с — sing-box отвалится
        по таймауту раньше, чем пойдёт голос;
      * замеренно медленнее UDP_MIN_SPEED_KBPS — такие и UDP-пакеты теряют
        (на проверке: 2,5 КБ/с и 20% потерь)."""
    udp = [r for r in results if r.working and r.udp and r.proxy.type == ProxyType.SOCKS5
           and _latency(r) <= UDP_MAX_TCP_LATENCY_MS
           and (r.speed_kbps is None or r.speed_kbps >= UDP_MIN_SPEED_KBPS)]
    return diversify(sorted(udp, key=lambda r: (is_unstable(r), r.udp_ms)))[:limit]


def _outbound_for(ptype: ProxyType, tag: str, host: str, port: int) -> dict:
    base = {"tag": tag, "server": host, "server_port": port, "connect_timeout": CONNECT_TIMEOUT}
    if ptype == ProxyType.SOCKS5:
        return {"type": "socks", **base, "version": "5"}
    if ptype == ProxyType.SOCKS4:
        return {"type": "socks", **base, "version": "4a"}
    if ptype == ProxyType.HTTPS:
        return {"type": "http", **base}
    raise ValueError(f"неизвестный тип {ptype}")


def _tag(prefix: str, i: int, r: CheckResult) -> str:
    return f"proxy-{prefix}{i}-{r.proxy.host.replace('.', '_')}-{r.proxy.port}"


def _routing_rules(routing: RoutingSettings, has_udp_group: bool, main_tag: str = URLTEST_TAG) -> tuple[list[dict], str]:
    """Правила маршрутизации по приложениям (идут после «локальная сеть —
    напрямую») и итоговый outbound для всего остального. ``main_tag`` — куда
    идёт трафик «через прокси»: группа автовыбора или закреплённый прокси."""
    mode = routing.effective_mode()
    names = routing.process_names()
    # QUIC (UDP 443) прокси не пропустят — отклоняем сразу, чтобы браузер
    # мгновенно откатился на обычный TCP/HTTPS
    quic_reject = {"network": "udp", "port": 443, "action": "reject"}
    if has_udp_group:
        udp_rule = {"network": "udp", "outbound": UDP_URLTEST_TAG}
    else:
        # через прокси без UDP голос не пойдёт точно — пробуем напрямую
        udp_rule = {"process_name": DISCORD_PROCESSES, "network": "udp", "outbound": "direct"}

    if mode == MODE_ONLY:
        if not names:
            return [], "direct"
        rules = [{"process_name": names, **quic_reject}]
        if has_udp_group:
            rules.append({"process_name": names, "network": "udp", "outbound": UDP_URLTEST_TAG})
        # без группы с UDP их UDP (кроме QUIC) уходит напрямую — по final
        rules.append({"process_name": names, "network": "tcp", "outbound": main_tag})
        return rules, "direct"

    rules = []
    if mode == MODE_EXCEPT:
        rules.append({"process_name": names, "outbound": "direct"})  # раньше отказа QUIC: им QUIC можно
    rules += [quic_reject, udp_rule]
    return rules, main_tag


def build_config(
    results: list[CheckResult],
    *,
    max_proxies: int = 15,
    interface_name: str = TUN_INTERFACE_NAME,
    tun_address: str = TUN_ADDRESS,
    bypass_process_paths: list[str] | None = None,
    routing: RoutingSettings | None = None,
    pinned: str | None = None,
    countries: list[str] | None = None,
) -> tuple[dict, dict]:
    """Собрать dict конфига sing-box и отдельно dict с метаинформацией для
    логов/README (её НЕЛЬЗЯ класть в сам файл конфига — sing-box строго
    валидирует JSON и падает на незнакомых полях).

    ``pinned`` — адрес закреплённого прокси: трафик идёт через него, а если он
    умрёт, программа переключит группу-переключатель (selector) на автовыбор
    через API sing-box и вернёт обратно, когда он оживёт. ``countries`` —
    разрешённые страны (пусто — любые).

    Поднимает ValueError, если рабочих прокси вообще нет — запускать VPN
    не из чего."""

    all_results = results
    results, countries_ok = filter_countries(results, countries)
    chosen, used_types = pick_proxies(results, max_proxies)
    if not chosen:
        raise ValueError("нет ни одного рабочего прокси — сначала обнови список")

    outbounds = []
    tags = []
    tag_by_addr: dict[str, str] = {}
    for i, r in enumerate(chosen):
        tag = _tag("", i, r)
        outbounds.append(_outbound_for(r.proxy.type, tag, r.proxy.host, r.proxy.port))
        tags.append(tag)
        tag_by_addr[r.proxy.address] = tag

    # Закреплённый прокси (на него фильтр стран не действует — выбран вручную).
    # Он обязательно и в группе автовыбора: так sing-box проверяет его каждые
    # 30 с, и программа видит, жив ли он.
    pin = next((r for r in all_results if r.working and r.proxy.address == pinned), None) if pinned else None
    pin_tag = None
    if pin is not None:
        pin_tag = tag_by_addr.get(pin.proxy.address)
        if pin_tag is None:
            pin_tag = _tag("p", 0, pin)
            outbounds.append(_outbound_for(pin.proxy.type, pin_tag, pin.proxy.host, pin.proxy.port))
            tags.append(pin_tag)
            tag_by_addr[pin.proxy.address] = pin_tag
    main_tag = PIN_SELECTOR_TAG if pin_tag else URLTEST_TAG

    # Отдельная группа для UDP (голос): только прокси, у которых при проверке
    # реально прошёл UDP. Прокси, попавший в обе группы, — один outbound.
    udp_chosen = pick_udp_proxies(results)
    udp_tags = []
    for i, r in enumerate(udp_chosen):
        tag = tag_by_addr.get(r.proxy.address)
        if tag is None:
            tag = _tag("u", i, r)
            outbounds.append(_outbound_for(r.proxy.type, tag, r.proxy.host, r.proxy.port))
        udp_tags.append(tag)

    outbounds.append(
        {
            "type": "urltest",
            "tag": URLTEST_TAG,
            "outbounds": tags,
            "url": URLTEST_URL,
            "interval": URLTEST_INTERVAL,
            # держимся за лучший по нашему рейтингу (порядок outbounds) и не
            # прыгаем на случайно «быстрый по пингу» — см. URLTEST_TOLERANCE_MS
            "tolerance": URLTEST_TOLERANCE_MS,
            # не рвём уже открытые соединения при смене прокси — иначе
            # у бесплатных прокси с «плавающей» скоростью сайты будут обрываться
            "interrupt_exist_connections": False,
        }
    )
    if pin_tag:
        outbounds.append({
            "type": "selector", "tag": PIN_SELECTOR_TAG, "outbounds": [pin_tag, URLTEST_TAG],
            "default": pin_tag, "interrupt_exist_connections": False,
        })
    if udp_tags:
        outbounds.append({
            "type": "urltest", "tag": UDP_URLTEST_TAG, "outbounds": udp_tags, "url": URLTEST_URL,
            "interval": URLTEST_INTERVAL, "tolerance": 200, "interrupt_exist_connections": False,
        })
    outbounds.append({"type": "direct", "tag": "direct"})

    routing = routing or RoutingSettings()
    app_rules, final = _routing_rules(routing, bool(udp_tags), main_tag)
    if routing.effective_mode() == MODE_ONLY:
        # Через прокси идут лишь выбранные приложения — и DNS не должен зависеть
        # от бесплатных прокси: если все они умрут, остальной интернет обязан
        # работать. DoH к 1.1.1.1 напрямую: провайдер не подменит ответ, а
        # выбранным приложениям хватает того, что их соединения идут через прокси.
        dns_server = {"type": "https", "tag": "direct-dns", "server": DNS_BOOTSTRAP_SERVER}
    else:
        dns_server = {"type": "https", "tag": "remote-dns", "server": DNS_BOOTSTRAP_SERVER, "detour": main_tag}

    # Трафик самой программы (проверка прокси, загрузка списков) — мимо VPN:
    # иначе проверка шла бы через уже выбранный прокси, а не с обычного
    # подключения, и обновлять список при включённом VPN было бы нельзя.
    bypass_rules = []
    if bypass_process_paths:
        bypass_rules.append({"process_path": list(dict.fromkeys(bypass_process_paths)), "outbound": "direct"})

    config = {
        "log": {"level": "info", "timestamp": True},
        # DNS — через DoH (TCP 443) поверх того же прокси: бесплатные прокси
        # почти никогда не умеют UDP, а обычный DNS у провайдера в РФ
        # может подменяться. DoH до 1.1.1.1 решает обе проблемы.
        "dns": {
            "servers": [dns_server],
            "final": dns_server["tag"],
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": interface_name,
                "address": [tun_address, TUN_ADDRESS_V6],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"action": "sniff"},
                # системные DNS-запросы перехватываем и решаем через DoH выше
                {"protocol": "dns", "action": "hijack-dns"},
                *bypass_rules,
                # локальная сеть (роутер, принтеры и т.п.) — напрямую
                {"ip_is_private": True, "outbound": "direct"},
                # по приложениям (см. _routing_rules): что через прокси, что
                # мимо; QUIC и UDP (голос) — там же
                *app_rules,
            ],
            "auto_detect_interface": True,
            "final": final,
        },
        "experimental": {"clash_api": {"external_controller": CLASH_API_ADDR}},
    }
    types_txt = " + ".join(t.value for t in used_types)
    fastest = _latency(chosen[0])
    subnets = len({subnet(r.proxy.host) for r in chosen})
    speeds = [r.speed_kbps for r in chosen if r.speed_kbps]
    speed_txt = f", скорость по замеру {min(speeds):.0f}–{max(speeds):.0f} КБ/с" if speeds else ""
    if any(is_slow(r) for r in chosen):
        speed_txt += (f" (ВНИМАНИЕ: быстрее {MIN_SPEED_KBPS} КБ/с прокси не нашлось — "
                      "взяты медленные; обнови список)")
    if udp_tags:
        udp_txt = f"Звонки/UDP: через {len(udp_tags)} прокси с проверенным UDP."
    else:
        udp_txt = ("Звонки/UDP: прокси с UDP не нашлось — голос Discord идёт напрямую "
                   "(мимо VPN); заработает ли он, зависит от провайдера.")
    extra = ""
    if countries:
        extra += (f" Страны: {', '.join(countries)}." if countries_ok else
                  f" ВНИМАНИЕ: в выбранных странах ({', '.join(countries)}) рабочих прокси нет — взяты любые.")
    if pin is not None:
        extra += f" Закреплён прокси {pin.proxy.address} (если перестанет отвечать — временно автовыбор)."
    elif pinned:
        extra += f" Закреплённый прокси {pinned} сейчас не работает — автовыбор лучшего."
    meta = {
        "proxy_tier_used": types_txt,
        "proxy_count": len(chosen),
        "udp_count": len(udp_tags),
        "chosen": [r.proxy.address for r in chosen],
        "pin_tag": pin_tag,
        "comment_ru": (
            f"В VPN {len(chosen)} прокси ({types_txt}), самый быстрый при проверке — "
            f"{fastest:.0f} мс{speed_txt}, из {subnets} разных подсетей. "
            "sing-box сам выбирает лучший и переключается при обрыве. "
            + udp_txt + f" Маршрутизация: {routing.describe()}." + extra
        ),
    }
    return config, meta


def write_config(results: list[CheckResult], out_path: pathlib.Path, **kwargs) -> dict:
    config, meta = build_config(results, **kwargs)
    storage.write_atomic(out_path, json.dumps(config, ensure_ascii=False, indent=2))
    return meta

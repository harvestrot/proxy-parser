"""Сбор бесплатных прокси, доступных из РФ без VPN.

Источники (словарь ``SOURCES`` — новый легко добавить):
  * proxyscrape.com — сама страница рисуется на JS (и закрыта Cloudflare),
    но данные она берёт из открытого API ``api.proxyscrape.com`` — его и
    используем: JSON с типом, страной, аптаймом и их замером скорости.
    Если API не открылся (сайт за Cloudflare, а Cloudflare из РФ режется:
    соединение «замирает» после ~16 КБ), те же данные берутся из их зеркала
    на GitHub.

Загрузка страниц вынесена в ``fetch(url) -> str``: по умолчанию напрямую,
а если источник недоступен — можно подставить загрузку через прокси.

«Фермы». По замеру 2 октября 2026 почти все публичные списки SOCKS5 забиты
одной фермой (45.74.31.0/24: 10 IP, 31 тыс. портов — 50–85% каждого списка,
у proxyscrape и proxifly тоже). Это одна точка, которая пересылает трафик на
чужие прокси; для VPN из неё всё равно берутся максимум 2 прокси, а проверка
тысяч её портов съедает лимиты источников, забивает роутер и вытесняет из
замера скорости остальных.
Поэтому с одного IP берётся не больше ``FARM_MAX_PER_IP`` портов, а из одной
подсети /24 — не больше ``FARM_MAX_PER_SUBNET`` адресов (случайная выборка,
за несколько обновлений пройдётся вся ферма).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import random
import re
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlencode

import requests

from .models import Proxy, ProxyType

log = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

Fetcher = Callable[[str], str]

PROXYSCRAPE_API = "https://api.proxyscrape.com/v4/free-proxy-list/get"

# Сколько прокси каждого типа брать из proxyscrape: в API их тысячи, а
# проверять все — долго. Берём заявленные быстрыми (их замер < 3 c),
# сортируем по аптайму. SOCKS5 в приоритете — их больше всего.
PROXYSCRAPE_LIMITS = {"socks5": 500, "socks4": 150, "http": 200}
PROXYSCRAPE_MAX_TIMEOUT_MS = 3000
# Зеркало API на GitHub (обновляется каждые 5 минут): raw.githubusercontent.com
# открывается из РФ, когда сам API (за Cloudflare) не грузится.
PROXYSCRAPE_GITHUB = "https://raw.githubusercontent.com/proxyscrape/free-proxy-list/main/proxies/protocols/{protocol}/data.json"
PROXYSCRAPE_GITHUB_MAX_AGE_S = 3 * 3600  # проверенные давнее — скорее всего, уже мертвы

_PS_TYPES = {"socks5": ProxyType.SOCKS5, "socks4": ProxyType.SOCKS4, "http": ProxyType.HTTPS}

FARM_MAX_PER_IP = 2       # портов с одного IP (несколько портов одного IP — один оператор)
FARM_MAX_PER_SUBNET = 6   # адресов из одной подсети /24 (в VPN из неё всё равно идут максимум 2)


@dataclass
class ScrapeStats:
    sources_ok: list[str] = field(default_factory=list)
    sources_failed: dict[str, str] = field(default_factory=dict)
    per_source: dict[str, int] = field(default_factory=dict)
    proxies_found: int = 0
    # какие адреса дал каждый источник (до слияния дублей) — для статистики источников
    members: dict[str, list[str]] = field(default_factory=dict)


class SourceProtected(Exception):
    """Сайт закрыт защитой от ботов — автоматически его не собрать
    (обходить такую защиту программа не пытается)."""


_BOT_CHECK_MARKERS = ("js_challenge", "cf-chl", "Just a moment...", "ddos-guard")


def looks_like_bot_check(status: int, text: str) -> bool:
    head = text[:8000]
    return status in (403, 429, 503) and any(m.lower() in head.lower() for m in _BOT_CHECK_MARKERS)


def direct_fetcher(timeout_s: float = 15.0, session: requests.Session | None = None) -> Fetcher:
    """Обычная загрузка напрямую (через текущее подключение)."""
    sess = session or requests.Session()
    sess.headers.update(DEFAULT_HEADERS)

    def fetch(url: str) -> str:
        resp = sess.get(url, timeout=timeout_s)
        if looks_like_bot_check(resp.status_code, resp.text):
            raise SourceProtected("сайт закрыт проверкой на бота — собрать его автоматически нельзя")
        resp.raise_for_status()
        return resp.text

    return fetch


# ------------------------------------------------------------ proxyscrape.com

def proxyscrape_url(protocol: str) -> str:
    query = {
        "request": "get_proxies",
        "proxy_format": "protocolipport",
        "format": "json",
        "protocol": protocol,
        "timeout": PROXYSCRAPE_MAX_TIMEOUT_MS,
        "limit": 2000,
    }
    return f"{PROXYSCRAPE_API}?{urlencode(query)}"


def _proxyscrape_items(items: list[dict], limit: int | None, *, uptime_key: str, latency_key: str,
                       country, country_code) -> list[Proxy]:
    """Общая часть разбора API и зеркала: лучшие по аптайму первыми, без
    HTTP без HTTPS, без мусорных адресов и без лишних портов «ферм»."""
    items = sorted(items, key=lambda p: p.get(uptime_key) or 0, reverse=True)
    out: list[Proxy] = []
    for p in items:
        ptype = _PS_TYPES.get(str(p.get("protocol", "")).lower())
        if ptype is None:
            continue
        # HTTP-прокси без поддержки HTTPS (CONNECT) нам бесполезны
        if ptype == ProxyType.HTTPS and not p.get("ssl"):
            continue
        try:
            host, port = str(p["ip"]), int(p["port"])
        except (KeyError, ValueError, TypeError):
            continue
        if not 0 < port < 65536 or not _is_public_ipv4(host):
            continue
        latency = p.get(latency_key)
        out.append(Proxy(
            host=host, port=port, type=ptype,
            country=country(p), country_code=country_code(p),
            anonymity=p.get("anonymity"),
            source_latency_ms=int(latency) if isinstance(latency, (int, float)) else None,
            source="proxyscrape.com",
        ))
    # фермы режем до лимита: иначе лучшие по аптайму места займёт одна ферма
    out = limit_farms(out)
    return out if limit is None else out[:limit]


def parse_proxyscrape(text: str, limit: int | None = None) -> list[Proxy]:
    data = json.loads(text)
    items = [p for p in data.get("proxies", []) if isinstance(p, dict) and p.get("alive", True)]
    return _proxyscrape_items(
        items, limit, uptime_key="uptime", latency_key="timeout",
        country=lambda p: (p.get("ip_data") or {}).get("country"),
        country_code=lambda p: (p.get("ip_data") or {}).get("countryCode"))


def parse_proxyscrape_github(text: str, limit: int | None = None, now: float | None = None) -> list[Proxy]:
    """Зеркало на GitHub: список объектов с ``uptime_percent``, ``latency_ms``
    и ``last_checked``. Как и в запросе к API, берём только с откликом до
    PROXYSCRAPE_MAX_TIMEOUT_MS и проверенные недавно."""
    now = now or time.time()
    data = json.loads(text)
    items = [p for p in (data if isinstance(data, list) else []) if isinstance(p, dict)
             and isinstance(p.get("latency_ms"), (int, float)) and p["latency_ms"] <= PROXYSCRAPE_MAX_TIMEOUT_MS
             and now - (p.get("last_checked") or 0) <= PROXYSCRAPE_GITHUB_MAX_AGE_S]
    return _proxyscrape_items(
        items, limit, uptime_key="uptime_percent", latency_key="latency_ms",
        country=lambda p: p.get("country"), country_code=lambda p: p.get("country_code"))


def scrape_proxyscrape(fetch: Fetcher) -> list[Proxy]:
    """API proxyscrape, а если он не открылся — его зеркало на GitHub. После
    первой неудачи с API остальные типы сразу берутся из зеркала: если API
    не открылся раз, то и следующие запросы, скорее всего, ждали бы тот же
    таймаут."""
    out: list[Proxy] = []
    errors = []
    api_ok = True
    for protocol, limit in PROXYSCRAPE_LIMITS.items():
        if api_ok:
            try:
                out += parse_proxyscrape(fetch(proxyscrape_url(protocol)), limit)
                continue
            except Exception as exc:  # noqa: BLE001 — в т.ч. SourceProtected: зеркало защитой не закрыто
                api_ok = False
                errors.append(f"API: {exc}")
                log.info("proxyscrape: API не открылся (%s) — беру зеркало на GitHub", exc)
        try:
            out += parse_proxyscrape_github(fetch(PROXYSCRAPE_GITHUB.format(protocol=protocol)), limit)
        except SourceProtected:
            raise
        except Exception as exc:  # noqa: BLE001
            errors.append(f"GitHub {protocol}: {exc}")
    if not out and errors:
        raise RuntimeError("; ".join(errors))
    return merge(out)


# ------------------------------------------------- простые текстовые списки

_SCHEME_TYPES = {
    "socks5": ProxyType.SOCKS5, "socks5h": ProxyType.SOCKS5,
    "socks4": ProxyType.SOCKS4, "socks4a": ProxyType.SOCKS4,
    "http": ProxyType.HTTPS, "https": ProxyType.HTTPS,
}


def type_from_name(name: str) -> ProxyType:
    try:
        return _SCHEME_TYPES[name.strip().lower()]
    except KeyError:
        raise ValueError(f"неизвестный тип прокси {name!r} (ожидается socks5 / socks4 / http)") from None


# [схема://]IPv4:порт[разделитель хвост]. Хвост встречается в разных
# списках: «ip:port:United States» (hideip.me), «ip:port US-N-S +» (spys.me),
# «ip:port|...»; страну из «ip:port:Страна» забираем, остальное игнорируем.
_PLAIN_RE = re.compile(
    r"^(?:(?P<scheme>[a-z0-9]+)://)?(?P<host>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})"
    r"(?:(?P<sep>[:\s|,;])(?P<tail>.*))?$",
    re.IGNORECASE,
)


def _is_public_ipv4(host: str) -> bool:
    """Отсечь мусор вроде 0.0.0.0, 127.x, 10.x, 192.168.x — через такие
    адреса прокси снаружи быть не может."""
    try:
        return ipaddress.IPv4Address(host).is_global
    except ValueError:
        return False


def parse_plain_list(text: str, default_type: ProxyType | None, source: str) -> list[Proxy]:
    """Строки вида ``ip:port``, ``socks5://ip:port``, ``ip:port  # коммент``,
    ``ip:port:Страна``. Тип берётся из схемы в строке, иначе —
    ``default_type``; строки без типа (когда и он не задан), прокси с
    логином/паролем, частные/служебные адреса и мусор пропускаются."""
    out: list[Proxy] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or "@" in line.split()[0]:  # прокси с логином/паролем нам не подходят
            continue
        m = _PLAIN_RE.match(line)
        if m is None:
            continue
        ptype = _SCHEME_TYPES.get(m["scheme"].lower()) if m["scheme"] else default_type
        port = int(m["port"])
        host = m["host"]
        if ptype is None or not 0 < port < 65536 or not _is_public_ipv4(host):
            continue
        country = None
        if m["sep"] == ":" and m["tail"]:
            tail = m["tail"].strip()
            if ":" in tail:  # ip:port:логин:пароль — прокси с авторизацией
                continue
            if tail and not tail[0].isdigit() and len(tail) <= 40:  # «United States»
                country = tail
        out.append(Proxy(host=host, port=port, type=ptype, source=source, country=country))
    return out


def plain_source(name: str, url: str, default_type: ProxyType | None, limit: int | None = None,
                 rng: random.Random | None = None) -> Callable[[Fetcher], list[Proxy]]:
    """Источник «текстовый список по ссылке». Если прокси больше ``limit`` —
    берётся случайная выборка: за несколько обновлений пройдём весь список
    (а хорошие запомнит репутация)."""
    def collect(fetch: Fetcher) -> list[Proxy]:
        found = merge(parse_plain_list(fetch(url), default_type, name))
        if not found:
            raise RuntimeError("в списке не нашлось ни одного прокси (неверная ссылка или формат?)")
        # перемешать, урезать фермы и только потом брать лимит — иначе
        # выборка почти целиком состоит из портов одной фермы
        (rng or random).shuffle(found)
        found = limit_farms(found)
        return found if limit is None else found[:limit]
    return collect


# ------------------------------------------------------------------ всё вместе

# Встроенный набор — используется, если sources.json нет или он повреждён.
SOURCES: dict[str, Callable[[Fetcher], list[Proxy]]] = {
    "proxyscrape.com": scrape_proxyscrape,
}


def merge(proxies: list[Proxy]) -> list[Proxy]:
    """Убрать дубли по host:port (первый встреченный остаётся). Если у первого
    нет страны, а у дубля из другого источника есть — страна берётся оттуда:
    прокси из РФ тогда отсеиваются ещё до проверки."""
    best: dict[tuple[str, int], Proxy] = {}
    for p in proxies:
        kept = best.setdefault((p.host, p.port), p)
        if kept is not p and not kept.country_code and p.country_code:
            kept.country, kept.country_code = p.country, p.country_code
    return list(best.values())


def subnet24(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else host


def limit_farms(proxies: list[Proxy], per_ip: int = FARM_MAX_PER_IP, per_subnet: int = FARM_MAX_PER_SUBNET,
                keep: set[tuple[str, int]] | None = None) -> list[Proxy]:
    """Оставить (в том же порядке) не больше ``per_ip`` портов с одного IP и
    ``per_subnet`` адресов из одной подсети /24 — см. «Фермы» в начале модуля.
    Адреса из ``keep`` (уже показавшие себя прокси) остаются всегда, но
    занимают места в лимите."""
    by_ip: dict[str, int] = {}
    by_net: dict[str, int] = {}
    if keep:
        for p in proxies:
            if (p.host, p.port) in keep:
                by_ip[p.host] = by_ip.get(p.host, 0) + 1
                by_net[subnet24(p.host)] = by_net.get(subnet24(p.host), 0) + 1
    out: list[Proxy] = []
    for p in proxies:
        if keep and (p.host, p.port) in keep:
            out.append(p)
            continue
        net = subnet24(p.host)
        if by_ip.get(p.host, 0) >= per_ip or by_net.get(net, 0) >= per_subnet:
            continue
        by_ip[p.host] = by_ip.get(p.host, 0) + 1
        by_net[net] = by_net.get(net, 0) + 1
        out.append(p)
    return out


def scrape(
    fetch: Fetcher | None = None,
    *,
    fallback_fetch: Fetcher | None = None,
    sources: dict[str, Callable[[Fetcher], list[Proxy]]] | None = None,
) -> tuple[list[Proxy], ScrapeStats]:
    """Собрать прокси со всех источников. Ошибка одного источника не
    останавливает остальные. Если источник не открылся напрямую и задан
    ``fallback_fetch`` (например, через прокси) — пробуем через него."""
    fetch = fetch or direct_fetcher()
    stats = ScrapeStats()
    collected: list[Proxy] = []
    if sources is None:
        from .sources_config import load_sources  # noqa: PLC0415 — избегаем циклического импорта
        sources = load_sources()
    for name, collect in sources.items():
        try:
            found = collect(fetch)
        except SourceProtected as exc:
            log.warning("%s: %s — пропускаю", name, exc)
            stats.sources_failed[name] = str(exc)
            continue
        except Exception as exc:  # noqa: BLE001
            if fallback_fetch is None:
                log.warning("%s: не удалось загрузить (%s)", name, exc)
                stats.sources_failed[name] = str(exc)
                continue
            log.info("%s напрямую не открылся (%s) — пробую через прокси", name, exc)
            try:
                found = collect(fallback_fetch)
            except Exception as exc2:  # noqa: BLE001
                log.warning("%s: не удалось загрузить и через прокси (%s)", name, exc2)
                stats.sources_failed[name] = str(exc2)
                continue
        stats.sources_ok.append(name)
        stats.per_source[name] = len(found)
        stats.members[name] = [p.address for p in found]
        log.info("%s: %d прокси", name, len(found))
        collected += found
    result = merge(collected)
    stats.proxies_found = len(result)
    return result, stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    found, s = scrape()
    print(s)
    for p in found[:10]:
        print(p.address, p.type.value, p.country, p.source)

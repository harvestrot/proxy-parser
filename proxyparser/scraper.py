"""Сбор бесплатных прокси, доступных из РФ без VPN.

Источники (словарь ``SOURCES`` — новый легко добавить):
  * proxyscrape.com — сама страница рисуется на JS (и закрыта Cloudflare),
    но данные она берёт из открытого API ``api.proxyscrape.com`` — его и
    используем: JSON с типом, страной, аптаймом и их замером скорости.

Загрузка страниц вынесена в ``fetch(url) -> str``: по умолчанию напрямую,
а если источник недоступен — можно подставить загрузку через прокси.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import random
import re
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

_PS_TYPES = {"socks5": ProxyType.SOCKS5, "socks4": ProxyType.SOCKS4, "http": ProxyType.HTTPS}


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


def parse_proxyscrape(text: str, limit: int | None = None) -> list[Proxy]:
    data = json.loads(text)
    items = [p for p in data.get("proxies", []) if p.get("alive", True)]
    items.sort(key=lambda p: p.get("uptime") or 0, reverse=True)
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
        except (KeyError, ValueError):
            continue
        timeout = p.get("timeout")
        out.append(Proxy(
            host=host, port=port, type=ptype,
            country=(p.get("ip_data") or {}).get("country"),
            country_code=(p.get("ip_data") or {}).get("countryCode"),
            anonymity=p.get("anonymity"),
            source_latency_ms=int(timeout) if isinstance(timeout, (int, float)) else None,
            source="proxyscrape.com",
        ))
        if limit is not None and len(out) >= limit:
            break
    return out


def scrape_proxyscrape(fetch: Fetcher) -> list[Proxy]:
    out: list[Proxy] = []
    errors = []
    for protocol, limit in PROXYSCRAPE_LIMITS.items():
        try:
            out += parse_proxyscrape(fetch(proxyscrape_url(protocol)), limit)
        except SourceProtected:
            raise  # защита от ботов — не перебираем остальные запросы
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{protocol}: {exc}")
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
        if limit is not None and len(found) > limit:
            found = (rng or random).sample(found, limit)
        return found
    return collect


# ------------------------------------------------------------------ всё вместе

# Встроенный набор — используется, если sources.json нет или он повреждён.
SOURCES: dict[str, Callable[[Fetcher], list[Proxy]]] = {
    "proxyscrape.com": scrape_proxyscrape,
}


def merge(proxies: list[Proxy]) -> list[Proxy]:
    """Убрать дубли по host:port (первый встреченный остаётся)."""
    best: dict[tuple[str, int], Proxy] = {}
    for p in proxies:
        best.setdefault((p.host, p.port), p)
    return list(best.values())


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

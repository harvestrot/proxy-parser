"""Список источников прокси — в файле ``sources.json`` в папке программы.

Файл создаётся автоматически при первом запуске. Чтобы добавить источник,
допиши в "sources" запись вида::

    {"name": "мой список", "kind": "plain", "url": "https://.../socks5.txt",
     "type": "socks5", "enabled": true, "limit": 2000}

Виды источников (kind):
  * "plain" — текстовый список по ссылке: строки ``ip:port`` или
    ``socks5://ip:port`` (тип из строки важнее поля "type");
  * "proxyscrape" — встроенный API proxyscrape.com.

"limit" — сколько максимум брать из списка за одно обновление (случайная
выборка); "enabled": false — временно выключить, не удаляя.
"""
from __future__ import annotations

import json
import logging
import pathlib
from typing import Callable

from . import scraper, storage
from .paths import APP_DIR

log = logging.getLogger(__name__)

PROJECT_ROOT = APP_DIR
SOURCES_FILE = PROJECT_ROOT / "sources.json"
DEFAULT_PLAIN_LIMIT = 3000

DEFAULT_CONFIG = {
    "_help": (
        "Источники прокси. kind: plain (текстовый список ip:port по ссылке) или proxyscrape. "
        "type: socks5 / socks4 / http (для plain, если в строках нет схемы). "
        "limit: сколько максимум брать за одно обновление. enabled: true/false. "
        "После правки просто нажми «Обновить список»."
    ),
    "sources": [
        # Отбор по замеру 2 октября 2026 (прямое подключение из РФ, чистая
        # репутация, полная проверка и скорость у всех рабочих) + история 10
        # обновлений. «_note»: адресов / рабочих / годных в VPN (от 150 КБ/с,
        # отклик до 2,5 с) / из них от 500 КБ/с — и что теряем без источника.
        {"name": "monosans (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "1283 / 48 / 10 / 8 — главный: в нём 8 из 9 быстрых",
         "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"},
        {"name": "proxyscrape.com", "kind": "proxyscrape", "enabled": True,
         "_note": "657 / 28 / 5 / 4 — без него теряем 4 рабочих и быстрый, которого нет в monosans"},
        {"name": "proxifly http (GitHub)", "kind": "plain", "type": "http", "enabled": True, "limit": None,
         "_note": "HTTP: 4368 / 6 / 2 / 2 — быстрые HTTP-прокси, которых нет больше нигде",
         "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"},
        {"name": "openproxylist.xyz", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "3000 из 6,8 тыс. / 33 / 6 / 6 — запас, временами даёт уникальные",
         "url": "https://api.openproxylist.xyz/socks5.txt"},
        {"name": "ALIILAPRO (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "1564 / 16 / 5 / 4 — запас, временами даёт уникальные",
         "url": "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt"},
        # Ради UDP (звонки): сравнение 2 октября 2026 — 34 тыс. SOCKS5 из 27 списков,
        # рабочих 188, с настоящим UDP всего 4; эти три источника вместе дают их все.
        {"name": "elliottophellia (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "UDP: 906 / 73 рабочих / 2 с UDP (1 только тут) — маленький и очень «чистый»",
         "url": "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt"},
        {"name": "vmheaven (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "UDP: 1041 / 23 рабочих / 2 с UDP",
         "url": "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt"},
        {"name": "dpangestuw (GitHub)", "kind": "plain", "type": "socks5", "enabled": True, "limit": 2500,
         "_note": "UDP: 4882 / 73 рабочих / 2 с UDP (1 только тут); limit — чтобы не нагружать роутер",
         "url": "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/socks5_proxies.txt"},
    ],
    # Вырезаны по замеру 2 октября 2026 (вернуть — дописать запись выше):
    #  * proxifly SOCKS5 — https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt
    #    36,9 тыс. адресов (87% всей проверки), уникальных рабочих — 0 в 7 из 8
    #    обновлений. И вредил: поток подключений к 42 тыс. адресов забивал
    #    роутер/канал — с ним проверка нашла 16 рабочих из всех источников, без
    #    него 70 (годных в VPN 3 против 11), и вдвое быстрее.
    #  * iplocate — https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt
    #    ничего не теряем ни в одном замере: почти полная копия monosans.
    #  * monosans http — https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt
    #    всё, что в нём работает, есть в proxifly http.
    #
    # Проверены раньше и не дали ничего сверх оставленных (SOCKS5, 1–2 октября):
    #  Anonym0usWork1221, dpangestuw, ProxyScraper, hideip.me, vmheaven,
    #  ProxyGenerator, databay-labs, elliottophellia, spys.me, ErcinDedeoglu,
    #  TheSpeedX, hookzof (копия proxifly), openproxylist http (то же, что
    #  proxifly http); 0 рабочих: MuRongPIG (100 тыс.), zevtyardt, fyvri,
    #  Tsprnay, r00tee, jetkai, vakhov, roosterkid; третий круг (30 списков,
    #  включая API geonode) — 13,5 тыс. новых адресов, 0 быстрых; SOCKS4-списки
    #  всех источников — 0 быстрых.
    #  Оговорка: самые большие из этих сравнений тоже шли потоком в десятки
    #  тысяч подключений и могли недосчитать рабочих — но и тогда все быстрые
    #  находились в оставленных источниках.
}


def ensure_file(path: pathlib.Path | None = None) -> pathlib.Path:
    path = path or SOURCES_FILE
    if not path.exists():
        storage.write_atomic(path, json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2))
    return path


def build_sources(config: dict) -> dict[str, Callable[[scraper.Fetcher], list]]:
    out: dict[str, Callable] = {}
    for i, entry in enumerate(config.get("sources", [])):
        if not isinstance(entry, dict) or not entry.get("enabled", True):
            continue
        name = str(entry.get("name") or entry.get("url") or f"источник {i + 1}")
        kind = str(entry.get("kind", "plain")).lower()
        try:
            if kind == "proxyscrape":
                out[name] = scraper.scrape_proxyscrape
            elif kind == "plain":
                url = entry["url"]
                ptype = scraper.type_from_name(entry["type"]) if entry.get("type") else None
                limit = entry.get("limit", DEFAULT_PLAIN_LIMIT)
                out[name] = scraper.plain_source(name, url, ptype, int(limit) if limit else None)
            else:
                log.warning("sources.json: у «%s» неизвестный kind=%r — пропускаю", name, kind)
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            log.warning("sources.json: источник «%s» записан с ошибкой (%s) — пропускаю", name, exc)
    return out


def _read_text_any(path: pathlib.Path) -> str:
    """Файл правят в Блокноте: он может сохранить UTF-8 с BOM или в ANSI
    (cp1251) — читаем и так, и так, а не падаем на русских буквах."""
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1251")


def load_sources(path: pathlib.Path | None = None) -> dict[str, Callable[[scraper.Fetcher], list]]:
    path = ensure_file(path)
    try:
        config = json.loads(_read_text_any(path))
        if not isinstance(config, dict):
            raise ValueError("ожидается объект {\"sources\": [...]}")
    except (OSError, ValueError) as exc:
        log.error("sources.json не читается (%s) — использую встроенные источники", exc)
        return dict(scraper.SOURCES)
    sources = build_sources(config)
    if not sources:
        log.warning("В sources.json нет включённых источников — использую встроенные")
        return dict(scraper.SOURCES)
    return sources

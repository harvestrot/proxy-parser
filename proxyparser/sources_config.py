"""Список источников прокси — в файле ``sources.json`` в папке программы.

Файл создаётся автоматически при первом запуске. Чтобы добавить источник,
допиши в "sources" запись вида::

    {"name": "мой список", "kind": "plain", "url": "https://.../socks5.txt",
     "type": "socks5", "enabled": true, "limit": 2000}

Виды источников (kind):
  * "plain" — текстовый список по ссылке: строки ``ip:port`` или
    ``socks5://ip:port`` (тип из строки важнее поля "type");
  * "proxyscrape" — встроенный API proxyscrape.com;
  * "subscription" — подписка с узлами VLESS / VMess / Trojan / Shadowsocks
    (ссылки vless://… построчно или весь список в base64; см. nodes.py).

"limit" — сколько максимум брать из списка за одно обновление (случайная
выборка; у подписок по умолчанию DEFAULT_NODE_LIMIT); "enabled": false —
временно выключить, не удаляя.

Если файл — нетронутые источники по умолчанию прошлой версии программы, он
сам обновляется до новых (см. _maybe_upgrade); правленный руками не трогается.
"""
from __future__ import annotations

import json
import logging
import pathlib
from typing import Callable

from . import nodes, scraper, storage
from .paths import APP_DIR

log = logging.getLogger(__name__)

PROJECT_ROOT = APP_DIR
SOURCES_FILE = PROJECT_ROOT / "sources.json"
DEFAULT_PLAIN_LIMIT = 3000
DEFAULT_NODE_LIMIT = 300  # узлы проверяются через мост sing-box: больше за раз — дольше проверка

CONFIG_VERSION = 3  # растёт, когда меняются источники по умолчанию (см. _maybe_upgrade)

_RAW = "https://raw.githubusercontent.com"
DEFAULT_CONFIG = {
    "_help": (
        "Источники прокси. kind: plain (текстовый список ip:port по ссылке), proxyscrape или "
        "subscription (подписка с узлами VLESS/VMess/Trojan/Shadowsocks). "
        "type: socks5 / socks4 / http (для plain, если в строках нет схемы). "
        "limit: сколько максимум брать за одно обновление. enabled: true/false. "
        "После правки просто нажми «Обновить список»."
    ),
    "version": CONFIG_VERSION,
    "sources": [
        # Пересмотр 2 октября 2026 (анализ содержимого списков и их обновлений;
        # что из них реально работает с твоего подключения — в таблице
        # «Статистика источников» после каждого обновления). Главная находка:
        # 50–85% каждого SOCKS5-списка — порты ОДНОЙ фермы 45.74.31.0/24
        # (10 IP, 31 тыс. портов, пересылает на чужие прокси). Теперь лишние
        # порты ферм отбрасываются ещё до проверки (scraper.limit_farms), и
        # вместо «шума» проверяются разные прокси.
        # «_note»: адресов в списке / берётся после урезания ферм и лимита /
        # из них не в РФ и нет больше ни в одном источнике по умолчанию.
        {"name": "proxyscrape.com", "kind": "proxyscrape", "enabled": True,
         "_note": "SOCKS5: 2974 / 528 лучших по аптайму (все типы) / 53 — 83% SOCKS5 было фермой; "
                  "если API не открылся — берётся их зеркало на GitHub"},
        {"name": "monosans (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "677 / 132 / 11 — сдал: 520 адресов — ферма, из остальных больше половины в РФ; "
                  "оставлен, потому что маленький и перепроверяется каждый час",
         "url": f"{_RAW}/monosans/proxy-list/main/proxies/socks5.txt"},
        {"name": "proxifly socks5 (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "36,9 тыс. / 2714 / 1359 — вернулся: 31 тыс. его адресов были той самой фермой "
                  "(из-за неё его и вырезали); без неё — самый большой набор разных SOCKS5",
         "url": f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"},
        {"name": "dpangestuw (GitHub)", "kind": "plain", "type": "socks5", "enabled": True, "limit": 2500,
         "_note": "5165 / 1947 / 797 — второй по числу уникальных SOCKS5",
         "url": f"{_RAW}/dpangestuw/Free-Proxy/main/socks5_proxies.txt"},
        {"name": "vmheaven (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "1937 / 972 / 245 — половина списка — ферма 69.174.54.x",
         "url": f"{_RAW}/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt"},
        {"name": "ALIILAPRO (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "2572 / 457 / 132",
         "url": f"{_RAW}/ALIILAPRO/Proxy/main/socks5.txt"},
        {"name": "iplocate (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "1306 / 443 / 164 — вернулся: раньше был копией monosans, теперь у него свои; "
                  "перепроверяется каждые 30 минут",
         "url": f"{_RAW}/iplocate/free-proxy-list/main/protocols/socks5.txt"},
        {"name": "elliottophellia (GitHub)", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "906 / 146 / 20 — 80% списка — ферма, половина остальных в РФ; маленький, часто перепроверяется",
         "url": f"{_RAW}/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt"},
        {"name": "openproxylist.xyz", "kind": "plain", "type": "socks5", "enabled": True,
         "_note": "6,8 тыс., берётся 3000 — запас, временами даёт уникальные",
         "url": "https://api.openproxylist.xyz/socks5.txt"},
        # HTTP-прокси с HTTPS (CONNECT): для обычного трафика не хуже SOCKS5.
        {"name": "proxifly http (GitHub)", "kind": "plain", "type": "http", "enabled": True, "limit": None,
         "_note": "4368 / 4031 / 2799 — рабочих в нём мало, но попадаются быстрые, которых нет больше нигде",
         "url": f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"},
        {"name": "hproxy https (GitHub)", "kind": "plain", "type": "http", "enabled": True,
         "_note": "1745 / 1646 / 1203 — новый: HTTP-прокси, у которых их проверка прошла и по HTTPS; "
                  "в списке только живые на момент выгрузки (обновляется несколько раз в день)",
         "url": f"{_RAW}/hproxy-com/free-proxy-list/main/https.txt"},
        {"name": "maximilianfeix https (GitHub)", "kind": "plain", "enabled": True,
         "_note": "901 / 370 / 173 — новый: прокси всех типов (тип в строке), прошедшие проверку "
                  "сертификата TLS, ханипотов и подмены страниц; обновляется каждый час",
         "url": f"{_RAW}/maximilianfeix/free-proxy-list/main/https.txt"},
        {"name": "monosans http (GitHub)", "kind": "plain", "type": "http", "enabled": True,
         "_note": "217 / 198 / 75 — вернулся: маленький, перепроверяется каждый час",
         "url": f"{_RAW}/monosans/proxy-list/main/proxies/http.txt"},
        # Узлы VLESS / VMess / Trojan / Shadowsocks: трафик до них зашифрован,
        # проверяются через мост sing-box (nodes.py, bridge.py). Дополнительные
        # HTTP/SOCKS-списки (20 штук, 3 октября 2026) дали 1 быстрый прокси на
        # 9,3 тыс. новых адресов, а 533 узла этих подписок — 13 быстрых.
        # «_note»: ссылок в подписке / рабочих из проверенных / быстрых (от 500 КБ/с).
        {"name": "zhuhaiuk узлы (GitHub)", "kind": "subscription", "enabled": True, "limit": None,
         "_note": "17 / 10 из 16 и 6 из 15 / 6 и 3 — маленькая, но лучшая; обновляется каждый час",
         "url": f"{_RAW}/zhuhaiuk/free-nodes/main/nodes.txt"},
        {"name": "F0rc3Run узлы (GitHub)", "kind": "subscription", "enabled": True,
         "_note": "552 / 10 из 119 и 20 из 300 / 3 и 3 — «лучшие результаты» их проверки; 19 рабочих только у неё",
         "url": f"{_RAW}/F0rc3Run/F0rc3Run/main/Best-Results/proxies.txt"},
        {"name": "Epodonios узлы (GitHub)", "kind": "subscription", "enabled": True,
         "_note": "7744 / 3 из 120 и 1 из 300 / 2 и 1 — огромная, берётся случайная выборка",
         "url": f"{_RAW}/Epodonios/v2ray-configs/main/All_Configs_Sub.txt"},
        {"name": "Au1rxx узлы (GitHub)", "kind": "subscription", "enabled": False,
         "_note": "2000 ссылок / 2 из 120 и 1 из 300 / 1 и 0 — выключена: почти все ссылки ведут на адреса "
                  "Cloudflare с разными настройками, а узел у нас — адрес:порт (проверяется одна случайная ссылка)",
         "url": f"{_RAW}/Au1rxx/free-vpn-subscriptions/main/output/protocol/vless/v2ray-base64-0001.txt"},
        {"name": "awesome-vpn узлы (GitHub)", "kind": "subscription", "enabled": True, "limit": None,
         "_note": "40 / 1 из 40 и 1 из 36 / 1 и 1",
         "url": f"{_RAW}/awesome-vpn/awesome-vpn/master/all"},
    ],
    # Проверены 2 октября 2026 и не взяты (вернуть — дописать запись выше):
    #  * давно не обновляются: ClearProxy/checked-proxy-list (с марта 2026),
    #    Skillter/ProxyGather (с июля 2026), zebbern/Proxy-Scraper (с января
    #    2026), rdavydov/proxy-list, mmpx12, ShiftyTR (с 2023);
    #  * почти целиком ферма и копии оставленных (после урезания ферм своих
    #    адресов 15–65): hproxy socks5, maximilianfeix socks5, VPSLab,
    #    dinoz0rg, databay-labs, hideip.me, TheSpeedX, hookzof (копия proxifly);
    #    чуть больше своих у trio666/proxy-checker (~100) — кандидат на запас;
    #  * proxifly https — судя по портам (443/8443), это прокси, к которым
    #    подключаются по TLS, а не HTTP-прокси с CONNECT: наш тип не подходит;
    #  * огромные непроверенные свалки (десятки тысяч адресов, большинство не
    #    встречается ни в одном проверяемом списке): ebrasha/abdal-proxy-hub,
    #    ErcinDedeoglu, SoliSpirit, TuanMinPay, shubhamshendre;
    #  * раньше: 0 рабочих — MuRongPIG, zevtyardt, fyvri, Tsprnay, r00tee,
    #    jetkai, vakhov, roosterkid; SOCKS4-списки — 0 быстрых;
    #  * GeoNode API (proxylist.geonode.com) — проверен 2 октября 2026: ~3,8
    #    тыс. свежих, 2335 из них нет в списках выше, но из этих 2335 рабочих
    #    оказалось 5, быстрый — 1 (Индонезия, отклик 1,9 с), в ближней Европе —
    #    ни одного. Лишние 2,3 тыс. проверок на каждое обновление не окупаются;
    #  * 3 октября 2026 ещё 20 активных HTTP/SOCKS-списков (sunny9577, Zaeem20,
    #    Argh94, ProxyScraper, Anonym0usWork1221, Vann-Dev, ProxyGather,
    #    Thordata, proxygenerator1, xyzs996, KangProxy, Moleway, VMHeaven.io,
    #    komutan234, proxy-free, LoneKingCode, berkay-digital, spys.me,
    #    free-proxy-list.net, openproxylist http): 9,3 тыс. новых адресов — 8
    #    рабочих, 1 быстрый. Перепечатывают тот же пул, что и списки выше;
    #  * подписки узлов: rtwo2/FastNodes (verified_tls: 0 рабочих из 120),
    #    barry-far/V2ray-Configs (репозиторий заблокирован GitHub).
}

# Источники по умолчанию прошлых версий: (kind, url, type, enabled, limit).
# Если sources.json совпадает с одним из них — его не правили руками, и при
# обновлении программы он молча заменяется новыми источниками (старый
# остаётся рядом как sources.old.json).
_V1_SOURCES = (
    ("plain", f"{_RAW}/monosans/proxy-list/main/proxies/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("proxyscrape", None, None, True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "http", True, None),
    ("plain", "https://api.openproxylist.xyz/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/ALIILAPRO/Proxy/main/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
)
_V2_SOURCES = (
    ("proxyscrape", None, None, True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/monosans/proxy-list/main/proxies/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "socks5", True,
     DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/dpangestuw/Free-Proxy/main/socks5_proxies.txt", "socks5", True, 2500),
    ("plain", f"{_RAW}/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/ALIILAPRO/Proxy/main/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/iplocate/free-proxy-list/main/protocols/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt", "socks5", True,
     DEFAULT_PLAIN_LIMIT),
    ("plain", "https://api.openproxylist.xyz/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "http", True, None),
    ("plain", f"{_RAW}/hproxy-com/free-proxy-list/main/https.txt", "http", True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/maximilianfeix/free-proxy-list/main/https.txt", None, True, DEFAULT_PLAIN_LIMIT),
    ("plain", f"{_RAW}/monosans/proxy-list/main/proxies/http.txt", "http", True, DEFAULT_PLAIN_LIMIT),
)
_OLD_DEFAULTS = (
    _V1_SOURCES,  # 1.0.0
    _V1_SOURCES + (  # 1.1.0
        ("plain", f"{_RAW}/elliottophellia/proxylist/master/results/socks5/global/socks5_checked.txt",
         "socks5", True, DEFAULT_PLAIN_LIMIT),
        ("plain", f"{_RAW}/vmheaven/VMHeaven-Free-Proxy-Updated/main/socks5.txt", "socks5", True, DEFAULT_PLAIN_LIMIT),
        ("plain", f"{_RAW}/dpangestuw/Free-Proxy/main/socks5_proxies.txt", "socks5", True, 2500),
    ),
    _V2_SOURCES,  # 1.1.x–1.2.0: до узлов VLESS
)


def ensure_file(path: pathlib.Path | None = None) -> pathlib.Path:
    """Создать sources.json, если его нет, а нетронутый файл прошлой версии
    обновить (см. _maybe_upgrade) — и для обновления списка, и для кнопки
    «Источники…», чтобы там сразу открывался актуальный файл."""
    path = path or SOURCES_FILE
    if not path.exists():
        storage.write_atomic(path, json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2))
        return path
    try:
        config = json.loads(_read_text_any(path))
    except (OSError, ValueError):
        return path  # испорченный файл не трогаем — load_sources об этом скажет
    if isinstance(config, dict):
        _maybe_upgrade(path, config)
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
            elif kind == "subscription":
                limit = entry.get("limit", DEFAULT_NODE_LIMIT)
                out[name] = nodes.subscription_source(name, entry["url"], int(limit) if limit else None)
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


def _signature(sources) -> tuple | None:
    """Содержательная часть списка источников (без названий и заметок) —
    чтобы узнать нетронутый файл прошлой версии."""
    if not isinstance(sources, list):
        return None
    out = []
    for s in sources:
        if not isinstance(s, dict):
            return None
        ptype = s.get("type")
        out.append((str(s.get("kind", "plain")).lower(), s.get("url"),
                    ptype.lower() if isinstance(ptype, str) else None,
                    bool(s.get("enabled", True)), s.get("limit", DEFAULT_PLAIN_LIMIT)))
    return tuple(out)


def _is_outdated(config: dict) -> bool:
    version = config.get("version", 1)
    return not isinstance(version, int) or version < CONFIG_VERSION


def _maybe_upgrade(path: pathlib.Path, config: dict) -> dict:
    """sources.json создаётся один раз и дальше живёт рядом с программой —
    новые источники по умолчанию сами в него не попадут. Если файл —
    нетронутые источники по умолчанию прошлой версии, заменить его новыми
    (старый сохраняется как sources.old.json); если его правили руками — не
    трогать (подсказку пишет load_sources)."""
    if not _is_outdated(config) or _signature(config.get("sources")) not in _OLD_DEFAULTS:
        return config
    backup = path.with_name("sources.old.json")
    try:
        storage.write_atomic(backup, _read_text_any(path))
        storage.write_atomic(path, json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2))
    except OSError as exc:
        log.warning("sources.json не удалось обновить (%s) — беру новые источники по умолчанию без записи", exc)
    else:
        log.info("sources.json обновлён: новые источники по умолчанию (старый файл — %s)", backup.name)
    return DEFAULT_CONFIG


def load_sources(path: pathlib.Path | None = None) -> dict[str, Callable[[scraper.Fetcher], list]]:
    path = ensure_file(path)
    try:
        config = json.loads(_read_text_any(path))
        if not isinstance(config, dict):
            raise ValueError("ожидается объект {\"sources\": [...]}")
    except (OSError, ValueError) as exc:
        log.error("sources.json не читается (%s) — использую встроенные источники", exc)
        return dict(scraper.SOURCES)
    config = _maybe_upgrade(path, config)  # если файл не удалось перезаписать
    if _is_outdated(config):
        log.info("В sources.json свои правки — новые источники по умолчанию в него не добавлены. Чтобы "
                 "получить их, переименуй sources.json: при следующем обновлении он создастся заново")
    sources = build_sources(config)
    if not sources:
        log.warning("В sources.json нет включённых источников — использую встроенные")
        return dict(scraper.SOURCES)
    return sources

"""Бесплатные узлы VLESS / VMess / Trojan / Shadowsocks.

Публичные агрегаторы раздают «подписки» — списки ссылок вида vless://…,
vmess://…, trojan://…, ss://… (иногда весь список закодирован в base64). В
отличие от HTTP/SOCKS-прокси трафик до таких узлов зашифрован, и VLESS+Reality
ТСПУ пропускает куда лучше. По проверке 3 октября 2026 из 533 узлов шести
агрегаторов с подключения из РФ работали 24, быстрых (от 500 КБ/с) — 13; у 20
дополнительных HTTP/SOCKS-списков — 1 быстрый на 9,3 тыс. адресов.

Узел — это Proxy с типом VLESS/VMESS/TROJAN/SS, адресом сервера и исходной
ссылкой (Proxy.link); outbound для sing-box собирается из ссылки (outbound()).
Проверщик говорит только на SOCKS/HTTP, поэтому узлы проверяются через мост
(bridge.py): sing-box превращает каждый узел в SOCKS5 на 127.0.0.1.

Узел определяется адресом сервера и портом (как и обычный прокси): если у
подписки несколько ссылок на один host:port, остаётся первая.
"""
from __future__ import annotations

import base64
import functools
import ipaddress
import json
import random
import re
import urllib.parse as up
from typing import Callable

from . import scraper
from .models import Proxy, ProxyType

_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss)://", re.IGNORECASE)
_TYPES = {"vless": ProxyType.VLESS, "vmess": ProxyType.VMESS, "trojan": ProxyType.TROJAN, "ss": ProxyType.SS}

# Что sing-box (1.14) умеет; остальное (xhttp, kcp, quic, старые шифры SS,
# плагины SS) отбрасывается сразу — иначе sing-box не примет весь конфиг.
_TRANSPORTS = ("tcp", "raw", "none", "", "ws", "grpc", "httpupgrade")
_SS_METHODS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
_VMESS_SECURITY = {"auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-ctr"}
_FINGERPRINTS = {"chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"}
_SHORT_ID_RE = re.compile(r"^[0-9a-fA-F]{0,16}$")


def b64decode(text: str) -> str:
    """base64 в обоих алфавитах, с отрезанными «=» и без."""
    s = text.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")


def subscription_links(text: str) -> list[str]:
    """Ссылки на узлы из текста подписки (обычного или целиком в base64)."""
    body = text.strip()
    if "://" not in body[:300]:
        try:
            body = b64decode("".join(body.split()))
        except (ValueError, UnicodeError):
            return []
    return [line.strip() for line in body.splitlines() if _LINK_RE.match(line.strip())]


def _check_host(host: str) -> str:
    host = (host or "").strip("[]")
    if not host:
        raise ValueError("нет адреса сервера")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host  # домен
    if ip.version != 4 or not ip.is_global:
        raise ValueError("адрес не публичный IPv4")  # VPN работает только по IPv4
    return host


def _tls(q: dict, server: str, required: bool) -> dict | None:
    security = q.get("security", "").lower()
    if security not in ("tls", "reality"):
        if required and security != "none":
            security = "tls"  # Trojan без указания — всегда TLS
        else:
            return None
    tls: dict = {"enabled": True, "server_name": q.get("sni") or q.get("host") or server}
    if q.get("allowInsecure", q.get("insecure", "")).lower() in ("1", "true"):
        tls["insecure"] = True
    fp = q.get("fp", "").lower()
    if fp or security == "reality":
        tls["utls"] = {"enabled": True, "fingerprint": fp if fp in _FINGERPRINTS else "chrome"}
    if q.get("alpn"):
        tls["alpn"] = [a for a in q["alpn"].split(",") if a]
    if security == "reality":
        if not q.get("pbk"):
            raise ValueError("Reality без открытого ключа")
        sid = q.get("sid", "")
        if not _SHORT_ID_RE.match(sid):
            raise ValueError("Reality: неверный short_id")
        tls["reality"] = {"enabled": True, "public_key": q["pbk"], "short_id": sid}
    return tls


def _transport(q: dict) -> dict | None:
    kind = (q.get("type") or "tcp").lower()
    if kind not in _TRANSPORTS:
        raise ValueError(f"транспорт {kind} не поддерживается")
    if kind in ("tcp", "raw", "none", ""):
        if q.get("headerType", "").lower() == "http":
            raise ValueError("tcp с http-маскировкой не поддерживается")
        return None
    if kind == "ws":
        path = q.get("path") or "/"
        out: dict = {"type": "ws", "path": path}
        early = re.search(r"[?&]ed=(\d+)", path)
        if early:  # «ранние данные» xray: ?ed=2048 в пути
            out["path"] = re.sub(r"[?&]ed=\d+", "", path) or "/"
            out["max_early_data"] = int(early.group(1))
            out["early_data_header_name"] = "Sec-WebSocket-Protocol"
        if q.get("host"):
            out["headers"] = {"Host": q["host"]}
        return out
    if kind == "grpc":
        return {"type": "grpc", "service_name": q.get("serviceName") or q.get("path", "")}
    return {"type": "httpupgrade", "path": q.get("path") or "/", "host": q.get("host", "")}


def _parse_vmess(body: str) -> tuple[str, int, dict, dict]:
    j = json.loads(b64decode(body.split("#", 1)[0]))
    q = {"type": str(j.get("net") or "tcp"), "host": str(j.get("host") or ""), "path": str(j.get("path") or ""),
         "security": "tls" if str(j.get("tls", "")).lower() == "tls" else "", "sni": str(j.get("sni") or ""),
         "fp": str(j.get("fp") or ""), "alpn": str(j.get("alpn") or ""), "serviceName": str(j.get("path") or ""),
         "headerType": str(j.get("type") or "")}
    security = str(j.get("scy") or "auto").lower()
    if security not in _VMESS_SECURITY:
        raise ValueError(f"VMess: шифр {security} не поддерживается")
    server, port = _check_host(str(j.get("add", ""))), int(j.get("port"))
    ob = {"type": "vmess", "server": server, "server_port": port, "uuid": str(j["id"]),
          "security": security, "alter_id": int(j.get("aid") or 0)}
    return server, port, ob, q


def _parse_ss(body: str) -> tuple[str, int, dict]:
    body = body.split("#", 1)[0]
    if "?" in body:
        body, query = body.split("?", 1)
        if "plugin" in up.parse_qs(query):
            raise ValueError("Shadowsocks с плагином не поддерживается")
    body = body.rstrip("/")
    if "@" not in body:  # ss://BASE64(метод:пароль@хост:порт)
        body = b64decode(body)
    userinfo, hostport = body.rsplit("@", 1)
    userinfo = up.unquote(userinfo)
    if ":" not in userinfo:  # SIP002: ss://BASE64(метод:пароль)@хост:порт
        userinfo = b64decode(userinfo)
    method, password = userinfo.split(":", 1)
    method = method.lower()
    if method not in _SS_METHODS:
        raise ValueError(f"Shadowsocks: шифр {method} не поддерживается")
    host, port = hostport.rsplit(":", 1)
    server = _check_host(host)
    return server, int(port), {"type": "shadowsocks", "server": server, "server_port": int(port),
                               "method": method, "password": password}


@functools.lru_cache(maxsize=4096)
def _parse(link: str) -> tuple[ProxyType, str, int, str]:
    """(тип, сервер, порт, outbound в JSON). ValueError — ссылка не годится."""
    scheme, body = link.split("://", 1)
    scheme = scheme.lower()
    q: dict = {}
    if scheme == "vmess":
        server, port, ob, q = _parse_vmess(body)
    elif scheme == "ss":
        server, port, ob = _parse_ss(body)
    elif scheme in ("vless", "trojan"):
        u = up.urlsplit(link)
        # некоторые агрегаторы зашивают метку узла в параметр: type=tcp%23метка
        q = {k: v.split("#", 1)[0] for k, v in up.parse_qsl(u.query)}
        server, port = _check_host(u.hostname or ""), u.port
        if not port:
            raise ValueError("нет порта")
        secret = up.unquote(u.username or "")
        if not secret:
            raise ValueError("нет ключа узла")
        if scheme == "vless":
            ob = {"type": "vless", "server": server, "server_port": port, "uuid": secret}
            flow = q.get("flow", "")
            if flow:
                if flow != "xtls-rprx-vision":
                    raise ValueError(f"VLESS: flow {flow} не поддерживается")
                ob["flow"] = flow
        else:
            ob = {"type": "trojan", "server": server, "server_port": port, "password": secret}
    else:
        raise ValueError(f"неизвестная схема {scheme}")
    if not 0 < port < 65536:
        raise ValueError("неверный порт")
    if scheme != "ss":
        tls = _tls(q, server, required=(scheme == "trojan"))
        if tls:
            ob["tls"] = tls
        transport = _transport(q)
        if transport:
            ob["transport"] = transport
    return _TYPES[scheme], server, port, json.dumps(ob, ensure_ascii=False)


def parse_link(link: str, source: str | None = None) -> Proxy:
    """Proxy-узел по ссылке; ValueError — ссылка не годится."""
    link = link.strip()
    try:
        ptype, server, port, _ = _parse(link)
    except (KeyError, TypeError, IndexError, AttributeError) as exc:  # ValueError (и base64, и JSON) — как есть
        raise ValueError(f"ссылка не разобралась: {type(exc).__name__}") from exc
    return Proxy(host=server, port=port, type=ptype, source=source, link=link)


def outbound(proxy: Proxy) -> dict:
    """outbound sing-box для узла (без тега)."""
    if not proxy.link:
        raise ValueError(f"у узла {proxy.address} нет ссылки")
    return json.loads(_parse(proxy.link.strip())[3])


def label(proxy: Proxy) -> str:
    """«VLESS · Reality», «Trojan · ws» — чем узел защищён, для таблицы."""
    try:
        ob = outbound(proxy)
    except ValueError:
        return proxy.type.value
    tls = ob.get("tls") or {}
    security = "Reality" if (tls.get("reality") or {}).get("enabled") else ("TLS" if tls else "")
    parts = [security, (ob.get("transport") or {}).get("type", "")]
    return " · ".join(p for p in parts if p)


def parse_subscription(text: str, source: str, rng: random.Random | None = None) -> list[Proxy]:
    """Все годные узлы подписки; один host:port — один узел. ``rng`` —
    перемешать до слияния: ссылок на один адрес (CDN) бывает много, и за
    несколько обновлений так опробуются разные."""
    out = []
    for link in subscription_links(text):
        try:
            out.append(parse_link(link, source))
        except ValueError:
            continue
    if rng is not None:
        rng.shuffle(out)
    return scraper.merge(out)


def subscription_source(name: str, url: str, limit: int | None = None,
                        rng: random.Random | None = None) -> Callable[[scraper.Fetcher], list[Proxy]]:
    """Источник «подписка с узлами». Узлов больше ``limit`` — случайная
    выборка (за несколько обновлений пройдётся весь список, хорошие запомнит
    репутация); узлы одного сервера — как «ферма»: не больше двух портов с IP."""
    def collect(fetch: scraper.Fetcher) -> list[Proxy]:
        found = parse_subscription(fetch(url), name, rng or random.Random())
        if not found:
            raise RuntimeError("в подписке не нашлось ни одного годного узла (неверная ссылка или формат?)")
        found = scraper.limit_farms(found)
        return found if limit is None else found[:limit]
    return collect

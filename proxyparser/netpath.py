"""Сетевые обходные пути и проверки окружения.

* Загрузка страниц через наши же прокси — если источник списка заблокирован
  у провайдера, список можно обновить без стороннего VPN, через прокси из
  прошлой проверки.
* Поиск стороннего VPN: проверять прокси нужно с обычного подключения —
  ровно так, как к ним потом будет подключаться наш VPN. Если проверка
  идёт через чужой VPN, она показывает доступность прокси из страны того
  VPN, а не из РФ (там часть прокси недоступна или очень медленная).
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

from .models import Proxy
from .scraper import DEFAULT_HEADERS
from .upstream import connect_via

log = logging.getLogger(__name__)

_SSL_CTX = ssl.create_default_context()
_MAX_BODY = 5_000_000


async def http_get_via(proxy: Proxy, url: str, timeout: float = 12.0) -> str:
    """GET через прокси (HTTP/1.0 — без chunked, тело читаем до закрытия)."""
    parts = urlsplit(url)
    tls = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if tls else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    reader, writer = await connect_via(proxy, host, port, timeout)
    try:
        if tls:
            await asyncio.wait_for(writer.start_tls(_SSL_CTX, server_hostname=host), timeout)
        headers = "".join(f"{k}: {v}\r\n" for k, v in DEFAULT_HEADERS.items())
        writer.write(
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\n{headers}Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        await writer.drain()

        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_BODY:
                break
    finally:
        writer.close()

    raw = b"".join(chunks)
    head, _, body = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    status = status_line.split()
    if len(status) < 2 or status[1] != b"200":
        raise RuntimeError(f"ответ {status_line[:60]!r}")
    return body.decode("utf-8", errors="replace")


class ProxyFetcher:
    """Загрузчик страниц через список прокси: держится за прокси, пока тот
    работает, при ошибке переходит к следующему."""

    def __init__(self, proxies: list[Proxy], timeout: float = 12.0, max_switches: int = 10):
        self.proxies = list(proxies)
        self.timeout = timeout
        self.max_switches = max_switches
        self._idx = 0

    @property
    def current(self) -> Proxy | None:
        return self.proxies[self._idx] if self._idx < len(self.proxies) else None

    def __call__(self, url: str) -> str:
        switches = 0
        last_exc: Exception | None = None
        while self.current is not None and switches <= self.max_switches:
            proxy = self.current
            try:
                return asyncio.run(http_get_via(proxy, url, self.timeout))
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                log.info("Через %s не загрузилось (%s) — пробую следующий прокси", proxy.address, exc)
                self._idx += 1
                switches += 1
        raise RuntimeError(f"не удалось загрузить {url} ни через один прокси: {last_exc}")


# ---------------------------------------------------------------- сторонний VPN

_VPN_KEYWORDS = (
    "wireguard", "openvpn", "tap-windows", "tap-", "wintun", "vpn", "amnezia",
    "outline", "hiddify", "nekoray", "v2ray", "xray", "clash",
    "proton", "nordlynx", "windscribe", "radmin", "zerotier", "tailscale", "warp",
)
_OWN_ADAPTER = "sing-tun"


def match_vpn_adapters(adapters: list[str]) -> list[str]:
    """Отобрать сетевые адаптеры, похожие на VPN (по имени/описанию)."""
    found = []
    for name in adapters:
        low = name.lower()
        if _OWN_ADAPTER in low:
            continue
        if any(k in low for k in _VPN_KEYWORDS):
            found.append(name.strip())
    return found


def detect_external_vpn() -> list[str]:
    """Включённые VPN-адаптеры (Windows). На других ОС — пустой список."""
    if sys.platform != "win32":
        return []
    try:
        out = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-NetAdapter | Where-Object Status -eq 'Up' | "
                "ForEach-Object { $_.Name + ' | ' + $_.InterfaceDescription }",
            ],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout
    except Exception as exc:  # noqa: BLE001
        log.debug("Не удалось получить список адаптеров: %s", exc)
        return []
    return match_vpn_adapters([line for line in out.splitlines() if line.strip()])

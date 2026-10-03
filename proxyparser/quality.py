"""Реальная скорость прокси.

Задержка (пинг) не равна скорости: прокси может отвечать за 300 мс, но
качать 20 КБ/с. Для рабочих прокси качаем кусок файла с speed.cloudflare.com
и считаем КБ/с.

UDP (звонки, игры) больше не проверяется: через HTTP- и SOCKS4-прокси он не
идёт никогда, а среди бесплатных SOCKS5 рабочий UDP был у единиц и терял
пакеты — для звонков такие всё равно не годились.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass

from .models import Proxy
from .upstream import UpstreamError, connect_via

log = logging.getLogger(__name__)

SPEED_TEST_HOST = "speed.cloudflare.com"
SPEED_TEST_BYTES = 2_000_000
SPEED_TEST_MAX_SECONDS = 6.0
SPEED_MIN_BYTES = 64_000  # меньше (и сервер сам закрыл соединение) — замер недостоверен
# Данные пошли и встали дольше чем на столько — дальше не ждём. Так выглядит
# ограничение ТСПУ для зарубежных хостингов (Cloudflare, Hetzner, OVH,
# DigitalOcean…): соединение «замирает» после первых ~16–32 КБ. Скорость
# такого прокси — переданное, делённое на всё время с ожиданием, то есть
# честно низкая; а замер не держит слот все SPEED_TEST_MAX_SECONDS.
SPEED_STALL_S = 2.5
SPEED_FAILED = 0.0        # прокси не отдал данные — для VPN не годится

_SSL_CTX = ssl.create_default_context()


# ---------------------------------------------------------------- скорость

@dataclass(frozen=True)
class SpeedTarget:
    host: str = SPEED_TEST_HOST
    port: int = 443
    tls: bool = True
    path: str = f"/__down?bytes={SPEED_TEST_BYTES}"


async def measure_speed(
    proxy: Proxy,
    target: SpeedTarget = SpeedTarget(),
    timeout: float = 6.0,
    max_seconds: float = SPEED_TEST_MAX_SECONDS,
    stall_s: float = SPEED_STALL_S,
) -> float | None:
    """Скорость скачивания через прокси, КБ/с.

    * ``0.0`` — прокси не смог отдать данные (туннель/TLS не установились,
      данные не пошли): для VPN он бесполезен.
    * маленькое число — данные шли, но медленно или встали посреди замера
      (раньше такие получали None, «неизвестно», и пролезали в VPN наравне
      с быстрыми).
    * ``None`` — судить нельзя: тестовый сервер ответил не 200 (например,
      ограничил частоту запросов) или отдал слишком мало данных и закрыл
      соединение раньше времени.
    """
    try:
        reader, writer = await connect_via(proxy, target.host, target.port, timeout)
    except (UpstreamError, OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return SPEED_FAILED
    try:
        if target.tls:
            await asyncio.wait_for(writer.start_tls(_SSL_CTX, server_hostname=target.host), timeout)
        writer.write(
            f"GET {target.path} HTTP/1.1\r\nHost: {target.host}\r\nUser-Agent: Mozilla/5.0\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        # заголовки ответа
        status = await asyncio.wait_for(reader.readline(), timeout)
        if not status:
            return SPEED_FAILED  # прокси закрыл соединение, не дав ответа
        if b" 200" not in status:
            return None  # дело в тестовом сервере, а не в прокси
        while (await asyncio.wait_for(reader.readline(), timeout)) not in (b"\r\n", b""):
            pass
        got = 0
        first_byte_at = None
        eof = False
        end = time.monotonic() + max_seconds
        while time.monotonic() < end:
            wait = max(0.1, end - time.monotonic())
            if first_byte_at is not None:
                wait = min(wait, stall_s)
            try:
                chunk = await asyncio.wait_for(reader.read(65536), wait)
            except asyncio.TimeoutError:
                break
            if not chunk:
                eof = True
                break
            if first_byte_at is None:
                first_byte_at = time.monotonic()
            got += len(chunk)
        if first_byte_at is None:
            return SPEED_FAILED  # за всё окно замера не пришло ни байта
        if got < SPEED_MIN_BYTES and eof:
            return None  # сервер отдал мало и закрыл — по такому объёму не судят
        elapsed = max(time.monotonic() - first_byte_at, 0.05)
        return round(got / 1024 / elapsed, 1)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ssl.SSLError, UpstreamError, ValueError):
        return SPEED_FAILED
    finally:
        writer.close()

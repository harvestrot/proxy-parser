"""Установка реального (не тестового) туннеля через внешний прокси.

В отличие от checker.py, здесь соединение не закрывается — оно
возвращается наружу для дальнейшей ретрансляции байт клиента.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct

from .models import Proxy, ProxyType

StreamPair = tuple[asyncio.StreamReader, asyncio.StreamWriter]


class UpstreamError(Exception):
    pass


class UpstreamUnreachable(UpstreamError):
    """До самого прокси не удалось даже установить TCP-соединение."""


def _is_ip(host: str) -> int | None:
    """Вернуть 1 (IPv4) / 4 (IPv6), если host — литеральный IP, иначе None."""

    try:
        ipaddress.IPv4Address(host)
        return 1
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(host)
        return 4
    except ValueError:
        return None


async def _connect_upstream_socket(proxy: Proxy, timeout: float) -> StreamPair:
    try:
        return await asyncio.wait_for(asyncio.open_connection(proxy.host, proxy.port), timeout=timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise UpstreamUnreachable(f"прокси недоступен: {exc or type(exc).__name__}") from exc


async def via_socks5(proxy: Proxy, dst_host: str, dst_port: int, timeout: float) -> StreamPair:
    reader, writer = await _connect_upstream_socket(proxy, timeout)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 0x05 or resp[1] != 0x00:
            raise UpstreamError("SOCKS5: прокси отклонил метод аутентификации")

        ip_kind = _is_ip(dst_host)
        if ip_kind == 1:
            body = b"\x01" + socket.inet_aton(dst_host)
        elif ip_kind == 4:
            body = b"\x04" + socket.inet_pton(socket.AF_INET6, dst_host)
        else:
            host_b = dst_host.encode("idna") if any(ord(c) > 127 for c in dst_host) else dst_host.encode("ascii")
            body = b"\x03" + bytes([len(host_b)]) + host_b

        writer.write(b"\x05\x01\x00" + body + struct.pack(">H", dst_port))
        await writer.drain()

        head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if head[1] != 0x00:
            raise UpstreamError(f"SOCKS5 CONNECT отклонён, код={head[1]}")
        atyp = head[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == 0x03:
            n = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(n + 2), timeout=timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        return reader, writer
    except Exception:
        writer.close()
        raise


async def via_socks4(proxy: Proxy, dst_host: str, dst_port: int, timeout: float) -> StreamPair:
    reader, writer = await _connect_upstream_socket(proxy, timeout)
    try:
        ip_kind = _is_ip(dst_host)
        if ip_kind == 1:
            ip_bytes = socket.inet_aton(dst_host)
            domain_suffix = b""
        else:
            # SOCKS4a: невалидный IP 0.0.0.x сигналит прокси, что домен
            # идёт следом за userid — поддерживается большинством прокси.
            ip_bytes = b"\x00\x00\x00\x01"
            domain_suffix = dst_host.encode("ascii") + b"\x00"

        req = b"\x04\x01" + struct.pack(">H", dst_port) + ip_bytes + b"\x00" + domain_suffix
        writer.write(req)
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
        if resp[0] not in (0x00, 0x04) or resp[1] != 0x5A:
            raise UpstreamError(f"SOCKS4 CONNECT отклонён: {resp!r}")
        return reader, writer
    except Exception:
        writer.close()
        raise


async def via_http_connect(proxy: Proxy, dst_host: str, dst_port: int, timeout: float) -> StreamPair:
    reader, writer = await _connect_upstream_socket(proxy, timeout)
    try:
        hostport = f"{dst_host}:{dst_port}"
        req = f"CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\nProxy-Connection: Keep-Alive\r\n\r\n".encode("ascii")
        writer.write(req)
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if b" 200 " not in status_line and not status_line.rstrip().endswith(b"200"):
            raise UpstreamError(f"HTTP CONNECT отклонён: {status_line!r}")
        # Дочитываем оставшиеся заголовки ответа прокси до пустой строки.
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"\r\n", b""):
                break
        return reader, writer
    except Exception:
        writer.close()
        raise


_DIALERS = {
    ProxyType.SOCKS5: via_socks5,
    ProxyType.SOCKS4: via_socks4,
    ProxyType.HTTPS: via_http_connect,
}


async def connect_via(proxy: Proxy, dst_host: str, dst_port: int, timeout: float) -> StreamPair:
    dialer = _DIALERS.get(proxy.type)
    if dialer is None:
        raise UpstreamError(f"неизвестный тип прокси {proxy.type}")
    try:
        return await dialer(proxy, dst_host, dst_port, timeout)
    except UpstreamError:
        raise
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError) as exc:
        # Прокси оборвал соединение посреди рукопожатия (IncompleteReadError),
        # не ответил вовремя или прислал мусор — для вызывающего кода это всё
        # одно: «через этот прокси не вышло». Раньше IncompleteReadError
        # (это EOFError, не OSError) пролетал мимо обработчиков и ронял
        # всё обновление списка.
        raise UpstreamError(f"{proxy.type.value}: рукопожатие не удалось ({exc or type(exc).__name__})") from exc

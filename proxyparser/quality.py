"""Дополнительные проверки качества прокси: поддержка UDP и реальная скорость.

* UDP. Голос в Discord (и вообще звонки, игры) идёт по UDP. Через HTTP- и
  SOCKS4-прокси UDP не пройдёт никогда, а SOCKS5 умеет его только если
  сервер поддерживает команду UDP ASSOCIATE — у бесплатных прокси это
  редкость. Проверяем по-честному: шлём через прокси серию STUN-запросов
  (как делают звонки) на обычный порт и требуем, чтобы почти все вернулись.
* Скорость. Задержка (пинг) не равна скорости: прокси может отвечать за
  300 мс, но качать 20 КБ/с. Для лучших по задержке прокси качаем кусок
  файла с speed.cloudflare.com и считаем КБ/с.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass

from .models import Proxy, ProxyType
from .upstream import UpstreamError, connect_via

log = logging.getLogger(__name__)

# STUN-сервер на обычном (не DNS) порту: многие бесплатные прокси пропускают
# только DNS (порт 53), а обычный UDP режут или теряют — старая проверка одним
# DNS-запросом к 1.1.1.1:53 таких не ловила.
UDP_TEST_TARGET = ("stun.l.google.com", 19302)
# Несколько целей: прокси может резать одну — засчитывается любая ответившая.
UDP_TEST_TARGETS = (UDP_TEST_TARGET, ("stun.cloudflare.com", 3478))
DOH_URL = "https://1.1.1.1/dns-query"
UDP_PROBES = 5          # серия пакетов, а не один...
UDP_MIN_REPLIES = 4     # ...и терять можно не больше одного
UDP_PROBE_GAP_S = 0.2
SPEED_TEST_HOST = "speed.cloudflare.com"
SPEED_TEST_BYTES = 2_000_000
SPEED_TEST_MAX_SECONDS = 6.0
SPEED_MIN_BYTES = 64_000  # меньше (и сервер сам закрыл соединение) — замер недостоверен
SPEED_FAILED = 0.0        # прокси не отдал данные — для VPN не годится

_SSL_CTX = ssl.create_default_context()


# ---------------------------------------------------------------- UDP

def _stun_request(txid: bytes) -> bytes:
    """STUN Binding Request (RFC 5389): тип 0x0001, длина 0, magic cookie, 12 байт ID."""
    return struct.pack(">HHI", 0x0001, 0, 0x2112A442) + txid


_resolved: dict[str, str] = {}


def _is_real_ip(ip: str) -> bool:
    """Настоящий публичный IPv4. Отсекает «фиктивные» адреса: роутеры и
    VPN-клиенты в режиме fake-IP отдают для доменов адреса из 198.18.0.0/15,
    провайдер может подменить ответ на заглушку в частной сети."""
    try:
        return ipaddress.IPv4Address(ip).is_global
    except ValueError:
        return False


def _doh_lookup(host: str, timeout: float = 8.0) -> str | None:
    """A-запись через DNS-over-HTTPS прямо у 1.1.1.1 — мимо DNS роутера и
    провайдера (на практике роутер отдавал для stun.cloudflare.com фиктивный
    198.18.0.43, и UDP-проверка у всех прокси уходила в пустоту)."""
    import json
    import urllib.parse
    import urllib.request

    url = f"{DOH_URL}?{urllib.parse.urlencode({'name': host, 'type': 'A'})}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # без системного прокси
    with opener.open(req, timeout=timeout) as resp:
        answers = json.load(resp).get("Answer") or []
    return next((a["data"] for a in answers if a.get("type") == 1 and _is_real_ip(a.get("data", ""))), None)


async def _resolve_udp_target(target: tuple[str, int]) -> str | None:
    """IPv4 цели UDP-проверки (в SOCKS5-заголовке шлём IP); кешируется.
    Сначала DoH, потом системный DNS — но только с настоящим публичным адресом."""
    host = target[0]
    if host in _resolved:
        return _resolved[host]
    try:
        socket.inet_aton(host)
        ip: str | None = host  # уже IP (в том числе локальный — в тестах)
    except OSError:
        try:
            ip = await asyncio.to_thread(_doh_lookup, host)
        except Exception as exc:  # noqa: BLE001
            log.debug("DoH для %s не удался: %s", host, exc)
            ip = None
        if ip is None:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(host, target[1], family=socket.AF_INET,
                                                                     type=socket.SOCK_DGRAM)
                ip = next((i[4][0] for i in infos if _is_real_ip(i[4][0])), None)
            except OSError as exc:
                log.debug("Не удалось узнать адрес %s: %s", host, exc)
        if ip is None:
            log.warning("Не удалось узнать настоящий адрес %s для проверки UDP", host)
            return None
    _resolved[host] = ip
    return ip


def _dns_query(txid: int, name: str = "example.com") -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 вопрос
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)  # A, IN


class _UdpCollector(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        self.queue.put_nowait(data)


def _strip_socks5_udp_header(data: bytes) -> bytes:
    if len(data) < 4:
        raise ValueError("короткий UDP-ответ")
    atyp = data[3]
    if atyp == 0x01:
        offset = 4 + 4 + 2
    elif atyp == 0x04:
        offset = 4 + 16 + 2
    elif atyp == 0x03:
        offset = 4 + 1 + data[4] + 2
    else:
        raise ValueError(f"неизвестный ATYP {atyp}")
    return data[offset:]


async def _udp_associate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         proxy: Proxy, timeout: float) -> tuple[str, int] | None:
    """SOCKS5 UDP ASSOCIATE по уже открытому TCP; вернуть адрес UDP-реле."""
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    if await asyncio.wait_for(reader.readexactly(2), timeout) != b"\x05\x00":
        return None
    # адрес клиента заранее неизвестен — 0.0.0.0:0
    writer.write(b"\x05\x03\x00\x01" + b"\x00" * 6)
    await writer.drain()
    head = await asyncio.wait_for(reader.readexactly(4), timeout)
    if head[1] != 0x00:
        return None
    if head[3] == 0x01:
        relay_ip = socket.inet_ntoa(await asyncio.wait_for(reader.readexactly(4), timeout))
    elif head[3] == 0x04:
        relay_ip = socket.inet_ntop(socket.AF_INET6, await asyncio.wait_for(reader.readexactly(16), timeout))
    elif head[3] == 0x03:
        n = (await asyncio.wait_for(reader.readexactly(1), timeout))[0]
        relay_ip = (await asyncio.wait_for(reader.readexactly(n), timeout)).decode()
    else:
        return None
    relay_port = struct.unpack(">H", await asyncio.wait_for(reader.readexactly(2), timeout))[0]
    try:
        ip = ipaddress.ip_address(relay_ip)
        if ip.is_unspecified or (ip.is_private and not ipaddress.ip_address(proxy.host).is_private):
            relay_ip = proxy.host  # сервер сообщил «внутренний» адрес — шлём на внешний
    except ValueError:
        pass
    return None if relay_port == 0 else (relay_ip, relay_port)


async def _udp_series(proxy: Proxy, target: tuple[str, int], count: int, gap_s: float,
                      timeout: float, tail_s: float) -> list[float | None] | None:
    """Открыть UDP-сессию через SOCKS5 и отправить ``count`` пакетов с паузой
    ``gap_s`` — как настоящий поток игры/голоса. Вернуть RTT (мс) каждого
    пакета в порядке отправки (None — пакет потерян), или None, если UDP
    через прокси не поднялся вовсе. ``tail_s`` — сколько ждать ответы после
    последнего пакета. UDP-сессия живёт, пока открыто TCP-соединение."""
    if proxy.type != ProxyType.SOCKS5:
        return None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy.host, proxy.port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    transport = None
    try:
        relay = await _udp_associate(reader, writer, proxy, timeout)
        target_ip = await _resolve_udp_target(target) if relay else None
        if relay is None or target_ip is None:
            return None
        transport, proto = await asyncio.get_running_loop().create_datagram_endpoint(
            _UdpCollector, remote_addr=relay)
        socks_header = b"\x00\x00\x00\x01" + socket.inet_aton(target_ip) + struct.pack(">H", target[1])
        is_dns = target[1] == 53
        sent: dict[bytes, tuple[int, float]] = {}  # txid -> (номер пакета, когда отправлен)
        rtts: list[float | None] = [None] * count
        got = 0
        done_sending = asyncio.Event()

        async def send_series() -> None:
            for i in range(count):
                txid = os.urandom(2 if is_dns else 12)
                payload = _dns_query(int.from_bytes(txid, "big")) if is_dns else _stun_request(txid)
                sent[txid] = (i, time.monotonic())
                transport.sendto(socks_header + payload)
                if i < count - 1:
                    await asyncio.sleep(gap_s)
            done_sending.set()

        sender = asyncio.create_task(send_series())
        # до конца отправки ждём с запасом (таймер Windows округляет паузы
        # вверх на ~15 мс), после — ровно tail_s
        deadline = time.monotonic() + count * gap_s * 2 + tail_s + 1.0
        try:
            while got < count:
                if done_sending.is_set():
                    deadline = min(deadline, time.monotonic() + tail_s)
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                try:
                    data = await asyncio.wait_for(proto.queue.get(), min(left, max(gap_s, 0.05) * 2))
                except asyncio.TimeoutError:
                    continue
                try:
                    payload = _strip_socks5_udp_header(data)
                except (ValueError, IndexError):
                    continue
                hit = sent.pop(payload[:2] if is_dns else payload[8:20], None)  # pop: дубль не считаем
                if hit is not None:
                    rtts[hit[0]] = (time.monotonic() - hit[1]) * 1000
                    got += 1
        finally:
            sender.cancel()
        return rtts
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
        return None
    finally:
        if transport is not None:
            transport.close()
        writer.close()


def _median(values: list[float]) -> float:
    s = sorted(values)
    return s[len(s) // 2]


async def check_udp(proxy: Proxy, timeout: float = 5.0, target: tuple[str, int] | None = None) -> float | None:
    """Пропускает ли SOCKS5-прокси UDP: серия пакетов, почти все должны
    вернуться. Цели перебираются по очереди (прокси может резать одну) —
    засчитывается первая ответившая. Вернуть медианную задержку UDP в мс или None."""
    if proxy.type != ProxyType.SOCKS5:
        return None
    for t in ([target] if target else UDP_TEST_TARGETS):
        rtts = await _udp_series(proxy, t, UDP_PROBES, UDP_PROBE_GAP_S, timeout, tail_s=min(timeout, 2.0))
        ok = [r for r in rtts or () if r is not None]
        if len(ok) >= UDP_MIN_REPLIES:
            return round(_median(ok), 1)
    return None  # UDP не идёт или теряется — для звонков не годится


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
) -> float | None:
    """Скорость скачивания через прокси, КБ/с.

    * ``0.0`` — прокси не смог отдать данные (туннель/TLS не установились,
      данные не пошли): для VPN он бесполезен.
    * маленькое число — данные шли, но медленно (раньше такие получали
      None, «неизвестно», и пролезали в VPN наравне с быстрыми).
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
            try:
                chunk = await asyncio.wait_for(reader.read(65536), max(0.1, end - time.monotonic()))
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

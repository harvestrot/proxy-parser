"""Тесты quality.py: поддержка UDP у SOCKS5 (для звонков) и замер скорости.

Всё локально: фейковый SOCKS5 с честной UDP-пересылкой (UDP ASSOCIATE),
SOCKS5 без поддержки UDP, UDP-«DNS»-эхо и HTTP-сервер, отдающий файл.
"""
import asyncio
import pathlib
import socket
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import checker, quality  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)  # «DNS-ответ» с тем же ID


class Relay(asyncio.DatagramProtocol):
    """UDP-реле SOCKS5: пакеты клиента (с SOCKS-заголовком) -> цель, ответы -> клиенту.
    drop_every=N — терять каждый N-й пакет клиента (плохой канал)."""

    def __init__(self, drop_every: int | None = None):
        self.drop_every = drop_every
        self.count = 0

    def connection_made(self, transport):
        self.transport = transport
        self.client = None

    def datagram_received(self, data, addr):
        if data[:3] == b"\x00\x00\x00":  # от клиента
            self.count += 1
            if self.drop_every and self.count % self.drop_every == 0:
                return
            self.client = addr
            ip = socket.inet_ntoa(data[4:8])
            port = struct.unpack(">H", data[8:10])[0]
            self.target = (ip, port)
            self.transport.sendto(data[10:], self.target)
        elif self.client:  # ответ от цели
            hdr = b"\x00\x00\x00\x01" + socket.inet_aton(addr[0]) + struct.pack(">H", addr[1])
            self.transport.sendto(hdr + data, self.client)


def socks5_server(udp_supported: bool, drop_every: int | None = None):
    async def handler(reader, writer):
        await reader.readexactly(2)
        await reader.readexactly(1)
        writer.write(b"\x05\x00")
        head = await reader.readexactly(4)
        if head[3] == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        else:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        cmd = head[1]
        if cmd == 3:  # UDP ASSOCIATE
            if not udp_supported:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)  # command not supported
                await writer.drain()
                writer.close()
                return
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(lambda: Relay(drop_every), local_addr=("127.0.0.1", 0))
            relay_port = transport.get_extra_info("sockname")[1]
            # как многие реальные серверы, сообщаем 0.0.0.0 — клиент должен подставить адрес прокси
            writer.write(b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + struct.pack(">H", relay_port))
            await writer.drain()
            try:
                await reader.read()  # держим UDP-сессию, пока жив TCP
            finally:
                transport.close()
            return
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        tr, tw = await asyncio.open_connection(host, port)

        async def pipe(a, b):
            try:
                while True:
                    c = await a.read(65536)
                    if not c:
                        break
                    b.write(c)
                    await b.drain()
            except (ConnectionResetError, BrokenPipeError):
                pass
            finally:
                b.close()

        await asyncio.gather(pipe(reader, tw), pipe(tr, writer))
    return handler


def file_server(size: int):
    async def handler(reader, writer):
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % size)
        chunk = b"x" * 65536
        sent = 0
        while sent < size:
            part = chunk[: min(len(chunk), size - sent)]
            writer.write(part)
            await writer.drain()
            sent += len(part)
        writer.close()
    return handler


def trickle_server(chunk: int, pause: float):
    """Отдаёт «бесконечный» файл маленькими порциями с паузами — медленный канал."""
    async def handler(reader, writer):
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")
        try:
            for _ in range(200):
                writer.write(b"x" * chunk)
                await writer.drain()
                await asyncio.sleep(pause)
        except (ConnectionError, OSError):
            pass
        writer.close()
    return handler


async def main():
    loop = asyncio.get_running_loop()
    echo_tr, _ = await loop.create_datagram_endpoint(UdpEcho, local_addr=("127.0.0.1", 0))
    echo_port = echo_tr.get_extra_info("sockname")[1]

    udp_srv = await asyncio.start_server(socks5_server(True), "127.0.0.1", 0)
    no_udp_srv = await asyncio.start_server(socks5_server(False), "127.0.0.1", 0)
    p_udp = Proxy("127.0.0.1", udp_srv.sockets[0].getsockname()[1], ProxyType.SOCKS5)
    p_no_udp = Proxy("127.0.0.1", no_udp_srv.sockets[0].getsockname()[1], ProxyType.SOCKS5)

    ms = await quality.check_udp(p_udp, timeout=2, target=("127.0.0.1", echo_port))
    assert ms is not None, "UDP через честный SOCKS5 должен пройти"
    print(f"OK: UDP через SOCKS5 с UDP ASSOCIATE проходит ({ms} мс), адрес 0.0.0.0 корректно подменён")

    assert await quality.check_udp(p_no_udp, timeout=2, target=("127.0.0.1", echo_port)) is None
    print("OK: SOCKS5 без поддержки UDP распознан")

    assert await quality.check_udp(Proxy("127.0.0.1", 1, ProxyType.HTTPS), timeout=1) is None
    print("OK: HTTP/SOCKS4 не проверяются на UDP (не умеют его в принципе)")

    # быстрая проверка: прокси, теряющий каждый 2-й пакет, не проходит (нужно 4 из 5)
    lossy_srv = await asyncio.start_server(socks5_server(True, drop_every=2), "127.0.0.1", 0)
    p_lossy = Proxy("127.0.0.1", lossy_srv.sockets[0].getsockname()[1], ProxyType.SOCKS5)
    assert await quality.check_udp(p_lossy, timeout=2, target=("127.0.0.1", echo_port)) is None
    print("OK: UDP-проверка — серия пакетов; прокси с большими потерями отбракован")
    lossy_srv.close()

    big = await asyncio.start_server(file_server(1_500_000), "127.0.0.1", 0)
    small = await asyncio.start_server(file_server(10_000), "127.0.0.1", 0)
    t_big = quality.SpeedTarget("127.0.0.1", big.sockets[0].getsockname()[1], tls=False, path="/")
    t_small = quality.SpeedTarget("127.0.0.1", small.sockets[0].getsockname()[1], tls=False, path="/")
    speed = await quality.measure_speed(p_udp, t_big, timeout=2, max_seconds=3)
    assert speed and speed > 100, speed
    print(f"OK: скорость через прокси замерена: {speed:.0f} КБ/с")
    assert await quality.measure_speed(p_udp, t_small, timeout=2, max_seconds=2) is None
    print("OK: слишком мало данных — замер не засчитывается")

    # прокси принимает TCP и сразу закрывает его посреди SOCKS5-рукопожатия:
    # раньше IncompleteReadError ронял весь замер (и всё обновление списка)
    async def hang_up(reader, writer):
        writer.close()
    hang = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    p_hang = Proxy("127.0.0.1", hang.sockets[0].getsockname()[1], ProxyType.SOCKS5)
    assert await quality.measure_speed(p_hang, t_big, timeout=2, max_seconds=2) == quality.SPEED_FAILED
    hang_results = [CheckResult(p_hang, True, latency_ms=10), CheckResult(p_udp, True, latency_ms=20)]
    assert await checker.measure_top_speeds(hang_results, top=2, target=t_big) == 2
    assert hang_results[0].speed_kbps == 0 and hang_results[1].speed_kbps > 100
    print("OK: обрыв посреди рукопожатия — скорость 0 (в VPN не попадёт), остальные меряются")
    hang.close()

    # медленный прокси: данные идут, но ~20 КБ/с — должен получить честную
    # низкую скорость, а не «неизвестно» (раньше такие пролезали в VPN)
    slow = await asyncio.start_server(trickle_server(4096, 0.2), "127.0.0.1", 0)
    t_slow = quality.SpeedTarget("127.0.0.1", slow.sockets[0].getsockname()[1], tls=False, path="/")
    s = await quality.measure_speed(p_udp, t_slow, timeout=2, max_seconds=1.5)
    assert s is not None and 0 < s < 60, s
    print(f"OK: медленный прокси получает реальную низкую скорость ({s:.0f} КБ/с), а не «неизвестно»")
    slow.close()

    results = [
        CheckResult(p_udp, True, latency_ms=50),
        CheckResult(p_no_udp, True, latency_ms=60),
        CheckResult(Proxy("127.0.0.1", 1, ProxyType.SOCKS5), True, latency_ms=900),
        CheckResult(Proxy("127.0.0.1", 2, ProxyType.SOCKS5), False),
    ]
    n = await checker.measure_top_speeds(results, top=2, target=t_big)
    assert n == 2 and results[0].speed_kbps and results[1].speed_kbps and results[2].speed_kbps is None
    print("OK: скорость меряется только у лучших по задержке")

    # check_all заодно проверяет UDP у рабочих SOCKS5
    target = await asyncio.start_server(file_server(0), "127.0.0.1", 0)  # для TCP-пробы
    from proxyparser.checker import ProbeTarget
    probe = (ProbeTarget("127.0.0.1", target.sockets[0].getsockname()[1], tls=False, path="/generate_204"),)
    res = await checker.check_all([p_udp, p_no_udp], probes=probe, required_probes=(), timeout=2, udp_target=("127.0.0.1", echo_port))
    by_port = {r.proxy.port: r for r in res}
    assert by_port[p_udp.port].working and by_port[p_udp.port].udp
    assert by_port[p_no_udp.port].working and not by_port[p_no_udp.port].udp
    print("OK: check_all отмечает, какие рабочие SOCKS5 пропускают UDP")

    for srv in (udp_srv, no_udp_srv, big, small, target):
        srv.close()
    echo_tr.close()
    print("\nВсе тесты quality.py прошли.")


if __name__ == "__main__":
    asyncio.run(main())

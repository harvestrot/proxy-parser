"""Тесты quality.py: замер реальной скорости через прокси.

Всё локально: фейковый SOCKS5 и HTTP-серверы, отдающие файл быстро, медленно
или «замирающие» после первых килобайт (как режет ТСПУ).
"""
import asyncio
import pathlib
import socket
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import checker, quality  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402


def socks5_server():
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


def stalling_server(first: int):
    """Отдаёт ``first`` байт и «замирает», не закрывая соединение, — так выглядит
    ограничение ТСПУ для зарубежных хостингов (~16–32 КБ, потом тишина)."""
    async def handler(reader, writer):
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n" + b"x" * first)
        await writer.drain()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass
        writer.close()
    return handler


async def test_speed_spread_by_subnet():
    """Замер скорости не должен целиком уйти одной «ферме» с малой задержкой."""
    farm = [CheckResult(Proxy("45.74.31.%d" % (i % 10), 1000 + i, ProxyType.SOCKS5), True, latency_ms=50 + i)
            for i in range(30)]
    others = [CheckResult(Proxy("%d.20.30.40" % (100 + i), 1080, ProxyType.SOCKS5), True, latency_ms=900 + i)
              for i in range(3)]
    measured = []
    real = quality.measure_speed

    async def fake_measure(proxy, **kwargs):
        measured.append(proxy.host)
        return 100.0

    quality.measure_speed = fake_measure
    try:
        n = await checker.measure_top_speeds(farm + others, top=6)
    finally:
        quality.measure_speed = real
    assert n == 6
    assert sum(h.startswith("45.74.31.") for h in measured) == checker.SPEED_TEST_PER_SUBNET + 1, measured
    assert all(r.speed_kbps for r in others), "прокси из других сетей тоже должны получить замер"
    print("OK: места в замере скорости распределяются по подсетям — ферма не вытесняет остальных")


async def main():
    await test_speed_spread_by_subnet()

    srv_a = await asyncio.start_server(socks5_server(), "127.0.0.1", 0)
    srv_b = await asyncio.start_server(socks5_server(), "127.0.0.1", 0)
    p_a = Proxy("127.0.0.1", srv_a.sockets[0].getsockname()[1], ProxyType.SOCKS5)
    p_b = Proxy("127.0.0.1", srv_b.sockets[0].getsockname()[1], ProxyType.SOCKS5)

    big = await asyncio.start_server(file_server(1_500_000), "127.0.0.1", 0)
    small = await asyncio.start_server(file_server(10_000), "127.0.0.1", 0)
    t_big = quality.SpeedTarget("127.0.0.1", big.sockets[0].getsockname()[1], tls=False, path="/")
    t_small = quality.SpeedTarget("127.0.0.1", small.sockets[0].getsockname()[1], tls=False, path="/")
    speed = await quality.measure_speed(p_a, t_big, timeout=2, max_seconds=3)
    assert speed and speed > 100, speed
    print(f"OK: скорость через прокси замерена: {speed:.0f} КБ/с")
    assert await quality.measure_speed(p_a, t_small, timeout=2, max_seconds=2) is None
    print("OK: слишком мало данных — замер не засчитывается")

    # прокси принимает TCP и сразу закрывает его посреди SOCKS5-рукопожатия:
    # раньше IncompleteReadError ронял весь замер (и всё обновление списка)
    async def hang_up(reader, writer):
        writer.close()
    hang = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    p_hang = Proxy("127.0.0.1", hang.sockets[0].getsockname()[1], ProxyType.SOCKS5)
    assert await quality.measure_speed(p_hang, t_big, timeout=2, max_seconds=2) == quality.SPEED_FAILED
    hang_results = [CheckResult(p_hang, True, latency_ms=10), CheckResult(p_a, True, latency_ms=20)]
    assert await checker.measure_top_speeds(hang_results, top=2, target=t_big) == 2
    assert hang_results[0].speed_kbps == 0 and hang_results[1].speed_kbps > 100
    print("OK: обрыв посреди рукопожатия — скорость 0 (в VPN не попадёт), остальные меряются")
    hang.close()

    # медленный прокси: данные идут, но ~20 КБ/с — должен получить честную
    # низкую скорость, а не «неизвестно» (раньше такие пролезали в VPN)
    slow = await asyncio.start_server(trickle_server(4096, 0.2), "127.0.0.1", 0)
    t_slow = quality.SpeedTarget("127.0.0.1", slow.sockets[0].getsockname()[1], tls=False, path="/")
    s = await quality.measure_speed(p_a, t_slow, timeout=2, max_seconds=1.5)
    assert s is not None and 0 < s < 60, s
    print(f"OK: медленный прокси получает реальную низкую скорость ({s:.0f} КБ/с), а не «неизвестно»")
    slow.close()

    # «замирание» после первых КБ (ТСПУ): замер не ждёт всё окно, скорость — честно низкая
    stall = await asyncio.start_server(stalling_server(20_000), "127.0.0.1", 0)
    t_stall = quality.SpeedTarget("127.0.0.1", stall.sockets[0].getsockname()[1], tls=False, path="/")
    started = asyncio.get_running_loop().time()
    s = await quality.measure_speed(p_a, t_stall, timeout=2, max_seconds=6, stall_s=0.5)
    took = asyncio.get_running_loop().time() - started
    assert s is not None and 0 < s < quality.SPEED_MIN_BYTES / 1024, s
    assert took < 3, took
    print(f"OK: соединение «замерло» после 20 КБ — замер прерван через {took:.1f} с, скорость {s:.0f} КБ/с (медленный)")
    stall.close()

    results = [
        CheckResult(p_a, True, latency_ms=50),
        CheckResult(p_b, True, latency_ms=60),
        CheckResult(Proxy("127.0.0.1", 1, ProxyType.SOCKS5), True, latency_ms=900),
        CheckResult(Proxy("127.0.0.1", 2, ProxyType.SOCKS5), False),
    ]
    n = await checker.measure_top_speeds(results, top=2, target=t_big)
    assert n == 2 and results[0].speed_kbps and results[1].speed_kbps and results[2].speed_kbps is None
    print("OK: скорость меряется только у лучших по задержке")

    for srv in (srv_a, srv_b, big, small):
        srv.close()
    print("\nВсе тесты quality.py прошли.")


if __name__ == "__main__":
    asyncio.run(main())

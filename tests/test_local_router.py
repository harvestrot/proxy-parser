"""Сквозной тест local_router.py: настоящий SOCKS5-клиент -> наш роутер ->
фейковый upstream-прокси -> фейковая "целевая" TCP-служба (эхо).

Проверяем: роутер корректно ведёт серверный SOCKS5-хендшейк с клиентом,
устанавливает туннель через upstream и ретранслирует данные в обе стороны;
также проверяем автоматическое переключение на второй прокси, если первый
(в приоритете) отказывает.
"""
import asyncio
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser.local_router import _accept, ProxyPool  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402


async def _echo_target_server():
    async def handler(reader, writer):
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _fake_upstream_socks5_server(should_fail: bool, real_target_port: int):
    """Фейковый upstream SOCKS5-прокси: либо честно проксирует к
    real_target_port на 127.0.0.1, либо всегда отвечает отказом."""

    async def handler(reader, writer):
        await reader.readexactly(1)  # ver
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n)
        writer.write(b"\x05\x00")
        await writer.drain()

        head = await reader.readexactly(4)
        atyp = head[3]
        if atyp == 0x01:
            await reader.readexactly(4)
        elif atyp == 0x03:
            ln = (await reader.readexactly(1))[0]
            await reader.readexactly(ln)
        await reader.readexactly(2)  # port

        if should_fail:
            writer.write(bytes([0x05, 0x05, 0x00, 0x01]) + b"\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return

        # честно подключаемся к реальной тестовой "целевой" службе
        t_reader, t_writer = await asyncio.open_connection("127.0.0.1", real_target_port)
        writer.write(bytes([0x05, 0x00, 0x00, 0x01]) + b"\x7f\x00\x00\x01" + struct.pack(">H", real_target_port))
        await writer.drain()

        async def pipe(a, b):
            try:
                while True:
                    c = await a.read(4096)
                    if not c:
                        break
                    b.write(c)
                    await b.drain()
            finally:
                b.close()

        await asyncio.gather(pipe(reader, t_writer), pipe(t_reader, writer))

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _socks5_client_roundtrip(router_host: str, router_port: int, dst_host: str, dst_port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(router_host, router_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp == b"\x05\x00", f"unexpected method response {resp!r}"

    host_b = dst_host.encode("ascii")
    req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack(">H", dst_port)
    writer.write(req)
    await writer.drain()

    head = await reader.readexactly(4)
    assert head[1] == 0x00, f"CONNECT через роутер отклонён, rep={head[1]}"
    atyp = head[3]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n + 2)

    writer.write(payload)
    await writer.drain()
    echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=3.0)
    writer.close()
    return echoed


async def main() -> None:
    echo_server, echo_port = await _echo_target_server()

    # Прокси #1 (выше приоритет по индексу в списке) — всегда отказывает.
    bad_server, bad_port = await _fake_upstream_socks5_server(should_fail=True, real_target_port=echo_port)
    # Прокси #2 — рабочий, честно проксирует к эхо-серверу.
    good_server, good_port = await _fake_upstream_socks5_server(should_fail=False, real_target_port=echo_port)

    results = [
        CheckResult(proxy=Proxy(host="127.0.0.1", port=bad_port, type=ProxyType.SOCKS5), working=True, latency_ms=1.0),
        CheckResult(proxy=Proxy(host="127.0.0.1", port=good_port, type=ProxyType.SOCKS5), working=True, latency_ms=2.0),
    ]
    pool = ProxyPool(results)

    async def on_client(reader, writer):
        await _accept(reader, writer, pool, connect_timeout=3.0)

    router_server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    router_port = router_server.sockets[0].getsockname()[1]

    async with router_server, echo_server, bad_server, good_server:
        payload = b"hello-through-router"
        echoed = await _socks5_client_roundtrip("127.0.0.1", router_port, "example.invalid", 443, payload)
        assert echoed == payload, f"эхо не совпало: {echoed!r} != {payload!r}"
        print("OK: роутер корректно обслужил клиента, автоматически обойдя нерабочий прокси #1 и использовав рабочий #2")

        # после первого неудачного обращения прокси #1 должен быть помечен dead
        assert (("127.0.0.1", bad_port) in pool._dead)  # noqa: SLF001
        print("OK: нерабочий прокси помечен как dead и больше не будет пробоваться первым")

    router_server.close()

    # порядок — по тому же фильтру, что и у VPN: быстрый, а не просто с лучшим пингом
    S5 = ProxyType.SOCKS5
    pool = ProxyPool([
        CheckResult(Proxy("9.0.0.1", 1080, S5), True, latency_ms=100, speed_kbps=20),    # лучший пинг, но 20 КБ/с
        CheckResult(Proxy("9.0.1.1", 1080, S5), True, latency_ms=400, speed_kbps=3000),
        CheckResult(Proxy("9.0.2.1", 1080, S5), True, latency_ms=300, speed_kbps=900),
    ])
    order = [p.host for p in pool.candidates()]
    assert order == ["9.0.1.1", "9.0.2.1", "9.0.0.1"], order
    print("OK: пул упорядочен по скорости и стабильности; медленный — последним, хоть и с лучшим пингом")

    pinned = ProxyPool(pool._results, pinned="9.0.0.1:1080")  # noqa: SLF001
    assert [p.host for p in pinned.candidates()] == ["9.0.0.1", "9.0.1.1", "9.0.2.1"]
    print("OK: закреплённый прокси — первым, остальные — запасом при его отказе")

    for p in pool.candidates():
        pool.mark_dead(p)
    assert len(pool.candidates()) == 3
    print("OK: все разом помечены нерабочими (сбой сети) — пул даёт им ещё шанс, а не отказывает всем")
    print("\nВсе сквозные тесты local_router.py прошли.")


if __name__ == "__main__":
    asyncio.run(main())

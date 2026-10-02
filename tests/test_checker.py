"""Тесты checker.py на локальных фейковых прокси и тестовом HTTP-сервере.

Сеть наружу в песочнице сборки закрыта, поэтому поднимаем всё локально:
  * «целевой» HTTP-сервер, отвечающий 204 на /generate_204;
  * фейковые SOCKS5 / SOCKS4 / HTTP-CONNECT прокси, которые честно
    пересылают данные к цели;
  * «лжеца» — прокси, который говорит «соединение установлено», но
    данные не передаёт (именно такие пропускала старая проверка);
  * TLS-сервер с самоподписанным сертификатом — имитация прокси,
    подменяющего сертификат: проверка обязана его отвергнуть.
"""
import asyncio
import pathlib
import socket
import ssl
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

from proxyparser.checker import ProbeTarget, check_proxy  # noqa: E402
from proxyparser.models import Proxy, ProxyType  # noqa: E402


async def _pipe(a, b):
    try:
        while True:
            chunk = await a.read(4096)
            if not chunk:
                break
            b.write(chunk)
            await b.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        b.close()


async def _relay_to(host, port, reader, writer):
    t_reader, t_writer = await asyncio.open_connection(host, port)
    await asyncio.gather(_pipe(reader, t_writer), _pipe(t_reader, writer))


async def _read_socks5_dst(reader):
    head = await reader.readexactly(4)
    if head[3] == 0x01:
        host = socket.inet_ntoa(await reader.readexactly(4))
    else:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode()
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    return host, port


def socks5_proxy(mode: str):
    """mode: 'good' | 'reject' | 'liar'"""
    async def handler(reader, writer):
        await reader.readexactly(2)
        await reader.readexactly(1)
        writer.write(b"\x05\x00")
        await writer.drain()
        host, port = await _read_socks5_dst(reader)
        if mode == "reject":
            writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
            await writer.drain()
            writer.close()
            return
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        if mode == "liar":
            await asyncio.sleep(0.1)
            writer.close()  # «туннель есть», а данных нет
            return
        await _relay_to(host, port, reader, writer)
    return handler


def socks4_proxy():
    async def handler(reader, writer):
        await reader.readexactly(2)
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        ip = socket.inet_ntoa(await reader.readexactly(4))
        while (await reader.readexactly(1)) != b"\x00":
            pass
        writer.write(b"\x00\x5a" + b"\x00" * 6)
        await writer.drain()
        await _relay_to(ip, port, reader, writer)
    return handler


def http_connect_proxy():
    async def handler(reader, writer):
        line = await reader.readline()
        hostport = line.split()[1].decode()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        host, port = hostport.rsplit(":", 1)
        await _relay_to(host, int(port), reader, writer)
    return handler


async def target_204_handler(reader, writer):
    req = await reader.readline()
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    if b"/generate_204" in req:
        writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    else:
        writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
    await writer.drain()
    writer.close()


async def _serve(handler, ssl_ctx=None):
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
    return server, server.sockets[0].getsockname()[1]


async def main() -> None:
    target, target_port = await _serve(target_204_handler)
    plain_probe = (ProbeTarget("127.0.0.1", target_port, tls=False),)

    cases = [
        ("SOCKS5 честный", ProxyType.SOCKS5, socks5_proxy("good"), True),
        ("SOCKS5 отказ", ProxyType.SOCKS5, socks5_proxy("reject"), False),
        ("SOCKS5 «лжец» (ок, но без данных)", ProxyType.SOCKS5, socks5_proxy("liar"), False),
        ("SOCKS4 честный", ProxyType.SOCKS4, socks4_proxy(), True),
        ("HTTP CONNECT честный", ProxyType.HTTPS, http_connect_proxy(), True),
    ]
    servers = [target]
    for name, ptype, handler, expected in cases:
        srv, port = await _serve(handler)
        servers.append(srv)
        res = await check_proxy(Proxy("127.0.0.1", port, ptype), probes=plain_probe, required_probes=(), timeout=2.0)
        status = "OK" if res.working == expected else "FAIL"
        print(f"{status}: {name} -> working={res.working} latency={res.latency_ms} err={res.error}")
        assert res.working == expected, name

    # подмена сертификата: TLS-цель с самоподписанным сертификатом
    # (готовый, из fixtures — чтобы тест не зависел от наличия openssl)
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(FIXTURES / "selfsigned_cert.pem", FIXTURES / "selfsigned_key.pem")
    mitm, mitm_port = await _serve(target_204_handler, ssl_ctx=sctx)
    servers.append(mitm)
    good, good_port = await _serve(socks5_proxy("good"))
    servers.append(good)
    res = await check_proxy(
        Proxy("127.0.0.1", good_port, ProxyType.SOCKS5),
        probes=(ProbeTarget("127.0.0.1", mitm_port, tls=True),),
        required_probes=(),
        timeout=2.0,
    )
    assert res.working is False and "CERTIFICATE" in (res.error or "").upper(), res
    print(f"OK: подменённый сертификат отвергнут ({res.error[:60]}...)")

    # «выборочный» MITM: основная проверка проходит, а адрес DNS-сервера
    # (обязательная проверка) отдаёт поддельный сертификат
    res = await check_proxy(
        Proxy("127.0.0.1", good_port, ProxyType.SOCKS5),
        probes=plain_probe,
        required_probes=(ProbeTarget("127.0.0.1", mitm_port, tls=True),),
        timeout=2.0,
    )
    assert res.working is False and "подменяет сертификат" in (res.error or ""), res
    print("OK: прокси, выборочно подменяющий сертификат DNS-сервера, отбракован как опасный")

    dead = await check_proxy(Proxy("127.0.0.1", 1, ProxyType.SOCKS5), probes=plain_probe, required_probes=(), timeout=1.5)
    assert dead.working is False
    print("OK: несуществующий прокси -> не рабочий")

    for s in servers:
        s.close()
    print("\nВсе тесты checker.py прошли.")


if __name__ == "__main__":
    asyncio.run(main())

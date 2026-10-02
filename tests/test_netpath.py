"""Тесты netpath.py: загрузка сайта через прокси (когда он заблокирован),
переключение на следующий прокси, распознавание стороннего VPN, а также
"""
import asyncio
import pathlib
import socket
import struct
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import netpath, scraper  # noqa: E402
from proxyparser.models import Proxy, ProxyType  # noqa: E402

FIXTURE = (pathlib.Path(__file__).parent / "fixtures" / "proxyscrape_sample.json").read_text(encoding="utf-8")


def start_servers():
    """В фоне: HTTP-сервер, отдающий образец ответа API, и честный SOCKS5-прокси."""
    loop = asyncio.new_event_loop()
    ports = {}
    ready = threading.Event()

    async def pipe(a, b):
        try:
            while True:
                c = await a.read(4096)
                if not c:
                    break
                b.write(c)
                await b.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            b.close()

    async def site(reader, writer):
        req = await reader.readline()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        body = FIXTURE.encode()
        if b"/v4/free-proxy-list/get" in req:
            writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)
        else:
            writer.write(b"HTTP/1.0 404 Not Found\r\n\r\n")
        await writer.drain()
        writer.close()

    async def socks5(reader, writer):
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
        await asyncio.gather(pipe(reader, tw), pipe(tr, writer))

    async def main():
        a = await asyncio.start_server(site, "127.0.0.1", 0)
        b = await asyncio.start_server(socks5, "127.0.0.1", 0)
        ports["site"] = a.sockets[0].getsockname()[1]
        ports["proxy"] = b.sockets[0].getsockname()[1]
        ready.set()
        await asyncio.Event().wait()

    threading.Thread(target=lambda: loop.run_until_complete(main()), daemon=True).start()
    ready.wait(5)
    return ports["site"], ports["proxy"]


def dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    site_port, proxy_port = start_servers()
    url = f"http://127.0.0.1:{site_port}/v4/free-proxy-list/get?protocol=socks5"

    html = asyncio.run(netpath.http_get_via(Proxy("127.0.0.1", proxy_port, ProxyType.SOCKS5), url, timeout=3))
    assert len(scraper.parse_proxyscrape(html)) == 3
    print("OK: ответ API загружен через SOCKS5 и распарсен")

    fetcher = netpath.ProxyFetcher(
        [Proxy("127.0.0.1", dead_port(), ProxyType.SOCKS5), Proxy("127.0.0.1", proxy_port, ProxyType.SOCKS5)],
        timeout=2,
    )
    assert scraper.parse_proxyscrape(fetcher(url))
    assert fetcher.current.port == proxy_port
    print("OK: мёртвый прокси пропущен, загрузчик переключился на рабочий и держится за него")

    adapters = [
        "Ethernet | Realtek PCIe GbE Family Controller",
        "Wi-Fi | Intel(R) Wi-Fi 6 AX201",
        "AmneziaVPN | AmneziaWG Tunnel",
        "Ethernet 2 | TAP-Windows Adapter V9",
        "sing-tun | WireGuard Tunnel",
        "vEthernet (WSL) | Hyper-V Virtual Ethernet Adapter",
    ]
    found = netpath.match_vpn_adapters(adapters)
    assert found == ["AmneziaVPN | AmneziaWG Tunnel", "Ethernet 2 | TAP-Windows Adapter V9"], found
    print("OK: сторонние VPN распознаны, обычные адаптеры и наш sing-tun — нет")

    print("\nВсе тесты netpath.py прошли.")


if __name__ == "__main__":
    main()

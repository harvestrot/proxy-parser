"""Мост к узлам (bridge.py): конфиг, подключение через вход узла и сквозная
проверка с настоящим sing-box — он же играет роль сервера Shadowsocks на
127.0.0.1 (без sing-box на машине сквозная часть пропускается)."""
import asyncio
import base64
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import bridge, checker, nodes, quality, singbox_manager  # noqa: E402
from proxyparser.checker import ProbeTarget  # noqa: E402
from proxyparser.upstream import UpstreamUnreachable, connect_via  # noqa: E402

SS_PASSWORD = "test-password-123"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def ss_link(port: int) -> str:
    return "ss://" + base64.b64encode(f"aes-128-gcm:{SS_PASSWORD}".encode()).decode() + f"@localhost:{port}#local"


async def target_204(reader, writer):
    req = await reader.readline()
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    if b"/generate_204" in req:
        writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    else:  # файл для замера скорости
        size = 1_500_000
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % size + b"x" * size)
    await writer.drain()
    writer.close()


def test_config_and_routing():
    node = nodes.parse_link(ss_link(8388))
    cfg = bridge.build_config([(node, 40001)])
    assert cfg["inbounds"] == [{"type": "mixed", "tag": "in0", "listen": "127.0.0.1", "listen_port": 40001}]
    assert cfg["outbounds"][0]["type"] == "shadowsocks" and cfg["outbounds"][0]["tag"] == "n0"
    assert cfg["route"]["rules"] == [{"inbound": ["in0"], "outbound": "n0"}]
    print("OK: конфиг моста — у каждого узла свой вход SOCKS5 на 127.0.0.1")

    async def no_bridge():
        try:
            await connect_via(node, "example.com", 80, 2)
        except UpstreamUnreachable as exc:
            return str(exc)
        raise AssertionError("узел без моста — недоступен")
    assert "мост" in asyncio.run(no_bridge())
    print("OK: узел без запущенного моста — «недоступен» (проверка не тратит на него время)")


async def end_to_end(exe: pathlib.Path) -> None:
    ss_port = free_port()
    folder = pathlib.Path(tempfile.mkdtemp())
    server_cfg = folder / "server.json"
    server_cfg.write_text(json.dumps({
        "log": {"level": "error"},
        "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ss_port,
                      "method": "aes-128-gcm", "password": SS_PASSWORD}],
        "outbounds": [{"type": "direct"}],
    }), encoding="utf-8")
    server = subprocess.Popen([str(exe), "run", "-c", str(server_cfg)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    target = await asyncio.start_server(target_204, "127.0.0.1", 0)
    t_port = target.sockets[0].getsockname()[1]
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", ss_port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        good = nodes.parse_link(ss_link(ss_port), "тест")
        # ключ Reality не той длины: наш разбор пропускает, а sing-box — нет
        broken = nodes.parse_link("vless://11111111-2222-3333-4444-555555555555@5.5.5.5:443"
                                  "?security=reality&sni=x.com&pbk=short&sid=ab")
        dead = nodes.parse_link(ss_link(free_port()))  # сервера на этом порту нет
        probe = (ProbeTarget("127.0.0.1", t_port, tls=False),)
        res = await checker.check_all([good, broken, dead], probes=probe, required_probes=(), timeout=5)
        by = {r.proxy.address: r for r in res}
        assert by[good.address].working, by[good.address]
        assert not by[broken.address].working and "мост" in by[broken.address].error, by[broken.address]
        assert not by[dead.address].working and "узел не соединил" in by[dead.address].error, by[dead.address]
        assert not bridge._ports  # noqa: SLF001 — после проверки мост остановлен
        print("OK: через мост узел проверяется обычной проверкой; узел, не принятый sing-box, выброшен, "
              "остальные работают; мёртвый — «узел не соединил»; после проверки мост закрыт")

        n = await checker.measure_top_speeds(
            [r for r in res if r.working], target=quality.SpeedTarget("127.0.0.1", t_port, tls=False, path="/big"))
        assert n == 1 and by[good.address].speed_kbps > 100, by[good.address].speed_kbps
        print(f"OK: скорость узла замерена через мост: {by[good.address].speed_kbps:.0f} КБ/с")
    finally:
        target.close()
        server.terminate()
        server.wait(timeout=5)


def main():
    test_config_and_routing()
    exe = singbox_manager.find_singbox()
    if exe is None:
        print("ПРОПУЩЕНО: sing-box не найден — сквозная проверка моста не выполнялась")
    else:
        asyncio.run(end_to_end(exe))
    print("\nВсе тесты bridge.py прошли.")


if __name__ == "__main__":
    main()

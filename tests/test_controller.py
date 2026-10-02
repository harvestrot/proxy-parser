"""Headless-тест AppController (логика GUI без tkinter).

Подменяем сбор с сайта на список прокси, которые указывают на локальные
фейковые SOCKS5/HTTP-серверы, а sing-box — на скрипт-заглушку, и
проверяем события, которые получил бы GUI.
"""
import asyncio
import json
import os
import pathlib
import socket
import stat
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proxyparser import controller as ctl_mod, scraper, singbox_config, singbox_manager, storage  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402
from proxyparser.scraper import ScrapeStats  # noqa: E402

TMP = pathlib.Path(tempfile.mkdtemp())
storage.WORKING_PROXIES_FILE = TMP / "working.json"
storage.ALL_PROXIES_FILE = TMP / "all.json"
singbox_manager.CONFIG_PATH = TMP / "config.json"
from proxyparser import geo, reputation  # noqa: E402
reputation.REPUTATION_FILE = TMP / "reputation.json"
from proxyparser import app_routing, app_settings  # noqa: E402
app_routing.ROUTING_FILE = TMP / "routing.json"  # не трогать настоящие настройки
app_settings.SETTINGS_FILE = TMP / "settings.json"
geo.lookup_ips = lambda ips, post=None: {}  # без сети


def _start_fake_network() -> tuple[int, int]:
    """В отдельном потоке: тестовый HTTP-сервер (204) и честный фейковый
    SOCKS5-прокси, пересылающий данные к цели. Возвращает (proxy_port, target_port)."""
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

    async def target(reader, writer):
        await reader.readline()
        while (await reader.readline()) not in (b"\r\n", b""):
            pass
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await writer.drain()
        writer.close()

    async def proxy(reader, writer):
        await reader.readexactly(2)
        await reader.readexactly(1)
        writer.write(b"\x05\x00")
        head = await reader.readexactly(4)
        if head[3] == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        else:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        port = int.from_bytes(await reader.readexactly(2), "big")
        writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
        await writer.drain()
        tr, tw = await asyncio.open_connection(host, port)
        await asyncio.gather(pipe(reader, tw), pipe(tr, writer))

    async def main():
        t = await asyncio.start_server(target, "127.0.0.1", 0)
        p = await asyncio.start_server(proxy, "127.0.0.1", 0)
        ports["target"] = t.sockets[0].getsockname()[1]
        ports["proxy"] = p.sockets[0].getsockname()[1]
        ready.set()
        await asyncio.Event().wait()

    threading.Thread(target=lambda: loop.run_until_complete(main()), daemon=True).start()
    ready.wait(5)
    return ports["proxy"], ports["target"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fake_singbox(name: str, line: str, exit_code: int | None) -> pathlib.Path:
    """Заглушка sing-box: печатает строку и висит (exit_code=None) либо
    завершается с кодом. На Windows — .cmd, иначе — shell-скрипт."""
    if sys.platform == "win32":
        exe = TMP / f"{name}.cmd"
        tail = "@ping -n 61 127.0.0.1 >nul" if exit_code is None else f"@exit /b {exit_code}"
        exe.write_text(f"@echo {line}\r\n{tail}\r\n")
        return exe
    exe = TMP / name
    tail = "exec sleep 60" if exit_code is None else f"exit {exit_code}"
    exe.write_text(f"#!/bin/sh\necho '{line}'\n{tail}\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


def _drain(ctl, until, timeout=10.0):
    events = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ev = ctl.events.get(timeout=0.2)
        except Exception:
            continue
        events.append(ev)
        if until(ev):
            return events
    raise AssertionError(f"не дождались события; получили: {[e[0] for e in events]}")


def _test_fetch_vpn_status() -> None:
    import http.server, json as _json
    payload = {"proxies": {
        "auto": {"type": "URLTest", "now": "proxy-1-5_6_7_8-1080",
                 "all": ["proxy-0-1_2_3_4-1080", "proxy-1-5_6_7_8-1080", "proxy-2-9_9_9_9-80"]},
        "proxy-0-1_2_3_4-1080": {"history": [{"delay": 0}]},
        "proxy-1-5_6_7_8-1080": {"history": [{"delay": 310}]},
        "proxy-2-9_9_9_9-80": {"history": []},
    }}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = _json.dumps(payload).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)
        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr = f"127.0.0.1:{srv.server_address[1]}"
    text, level, dead = ctl_mod.fetch_vpn_status(addr)
    assert not dead and level == "ok" and "5.6.7.8:1080" in text and "310" in text and "1 из 3" in text, text
    print("OK: статус VPN:", text)

    payload["proxies"]["proxy-1-5_6_7_8-1080"]["history"] = [{"delay": 0}]
    payload["proxies"]["proxy-2-9_9_9_9-80"]["history"] = [{"delay": 0}]
    text, level, dead = ctl_mod.fetch_vpn_status(addr)
    assert level == "warn", text
    print("OK: все мертвы ->", text)
    srv.shutdown()


def _test_pin_failover(ctl) -> None:
    """Закреплённый умер — переключатель уходит на автовыбор (после двух
    проверок подряд), ожил — возвращается. Clash API — фейковый."""
    import http.server

    pin_tag, other = ctl._pin_tag, "proxy-1-1_1_1_1-1080"
    state = {"proxies": {
        "auto": {"all": [pin_tag, other], "now": other},
        "pinned": {"all": [pin_tag, "auto"], "now": pin_tag},
        pin_tag: {"history": []},                 # неудачная проверка стирает историю
        other: {"history": [{"delay": 120}]},
    }}
    puts = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(state).encode()
            self.send_response(200); self.end_headers(); self.wfile.write(body)

        def do_PUT(self):
            name = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["name"]
            puts.append((self.path, name))
            state["proxies"]["pinned"]["now"] = name
            self.send_response(204); self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    real_api = singbox_config.CLASH_API_ADDR
    singbox_config.CLASH_API_ADDR = f"127.0.0.1:{srv.server_address[1]}"

    def tick():
        ctl._submit(ctl._pin_failover()).result(timeout=10)

    try:
        tick()
        assert puts == [], "одна неудачная проверка — ещё рано"
        tick()
        assert puts == [("/proxies/pinned", "auto")], puts
        text, _, _ = ctl_mod.fetch_vpn_status()
        assert "не отвечает" in text, text
        print("OK: закреплённый умер — после двух проверок подряд временно автовыбор:", text)

        state["proxies"][pin_tag]["history"] = [{"delay": 90}]
        tick()
        assert puts[-1] == ("/proxies/pinned", pin_tag), puts
        text, level, _ = ctl_mod.fetch_vpn_status()
        assert "закреплённый" in text and "90 мс" in text and level == "ok", text
        print("OK: закреплённый ожил — возвращаемся на него:", text)

        puts.clear()
        state["proxies"][pin_tag]["history"] = state["proxies"][other]["history"] = []
        tick(); tick()
        assert puts == [], "на старте (ещё никто не проверен) ничего не трогаем"
        print("OK: на старте, пока sing-box никого не проверил, переключатель не трогаем")
    finally:
        singbox_config.CLASH_API_ADDR = real_api
        srv.shutdown()
    ctl.pin_proxy(None)
    assert app_settings.load().pinned is None


def _test_auto_refresh_and_startup(ctl) -> None:
    now = time.time()
    ctl.settings.auto_refresh_hours = 3
    ctl._last_refresh_at = now - 4 * 3600
    assert ctl._auto_refresh_due(now)
    ctl._last_refresh_at = now - 3600
    assert not ctl._auto_refresh_due(now)
    ctl.settings.auto_refresh_hours, ctl._last_refresh_at = 0, 0
    assert not ctl._auto_refresh_due(now)
    ctl.settings.auto_refresh_hours = 3
    print("OK: фоновое обновление — по расписанию, выключается нулём")

    real_is_admin = singbox_manager.is_admin
    ctl.settings.auto_connect = True
    try:
        singbox_manager.is_admin = lambda: False
        ctl.startup()
        time.sleep(0.5)
        assert ctl.vpn_state == "off"
        singbox_manager.is_admin = lambda: True
        ctl.startup()
        _drain(ctl, lambda e: e == ("vpn", "on"), timeout=20)
        print("OK: автоподключение при запуске (без прав администратора — пропускается)")
        ctl.disconnect_vpn()
        _drain(ctl, lambda e: e == ("vpn", "off"))
    finally:
        singbox_manager.is_admin = real_is_admin
        ctl.settings.auto_connect = False


def main() -> None:
    good_port, target_port = _start_fake_network()
    dead_port = _free_port()

    # проверка в тесте идёт к локальному 204-серверу, а не в интернет
    from proxyparser import checker
    real_check_all = checker.check_all
    probes = (checker.ProbeTarget("127.0.0.1", target_port, tls=False),)
    checker.check_all = lambda proxies, **kw: real_check_all(proxies, probes=probes, required_probes=(), **kw)

    async def fake_speeds(results, **kw):  # без выхода в интернет: все живые «быстрые»
        for r in results:
            if r.working:
                r.speed_kbps = 1000.0
        return sum(1 for r in results if r.working)
    checker.measure_top_speeds = fake_speeds

    fake = [
        Proxy("127.0.0.1", good_port, ProxyType.SOCKS5, country="Testland"),
        Proxy("127.0.0.1", dead_port, ProxyType.SOCKS4),
    ]
    fixture_html = (ROOT / "tests" / "fixtures" / "proxyscrape_sample.json").read_text(encoding="utf-8")
    scraper.direct_fetcher = lambda **kw: (lambda url: fixture_html)  # «сайт открылся напрямую»
    # первая проверка находит сторонний VPN, после ответа «Да» — уже нет
    from proxyparser import netpath
    vpn_answers = [["Ethernet 2 | WireGuard Tunnel"], []]
    netpath.detect_external_vpn = lambda: vpn_answers.pop(0) if vpn_answers else []
    scraper.scrape = lambda *a, **kw: (fake, ScrapeStats(sources_ok=['test'], per_source={'test': len(fake)}, proxies_found=len(fake)))

    ctl = ctl_mod.AppController()
    assert ctl.results == []

    # 1) обновление списка
    ctl.refresh(timeout=1.5)
    ask = _drain(ctl, lambda e: e[0] == "ask")[-1]
    assert "WireGuard" in ask[1]
    ask[2]["answer"] = True  # «выключил, проверь ещё раз»
    ask[2]["event"].set()
    print("OK: перед проверкой спрашивает про сторонний VPN")
    events = _drain(ctl, lambda e: e == ("busy", False))
    kinds = [e[0] for e in events]
    assert "progress" in kinds and "results" in kinds, kinds
    results = next(e[1] for e in events if e[0] == "results")
    assert len(results) == 1 and results[0].proxy.port == good_port, results
    print(f"OK: refresh — {len(results)} рабочий из 2, события: {sorted(set(kinds))}")

    # 2) VPN с заглушкой sing-box
    fake_exe = _fake_singbox("sing-box", "INFO sing-box started (0.01s)", None)
    singbox_manager.find_singbox = lambda: fake_exe

    ctl.connect_vpn()
    _drain(ctl, lambda e: e == ("vpn", "on"))
    assert singbox_manager.CONFIG_PATH.exists()
    print("OK: VPN — конфиг записан, sing-box запущен, состояние 'on'")

    _drain(ctl, lambda e: e[0] == "vpn_info", timeout=6)
    print("OK: после подключения GUI получает статус VPN (vpn_info)")

    cfg = json.loads(singbox_manager.CONFIG_PATH.read_text())
    assert any("process_path" in r for r in cfg["route"]["rules"]), "нет правила «программа мимо VPN»"
    print("OK: в конфиге есть правило «трафик программы мимо VPN»")

    # маршрутизация по приложениям меняется на лету: настройки сохраняются,
    # VPN перезапускается с новыми правилами
    ctl.set_routing(app_routing.RoutingSettings(app_routing.MODE_ONLY, [app_routing.app_for_exe("chrome.exe")]))
    _drain(ctl, lambda e: e == ("vpn", "on"), timeout=20)
    cfg = json.loads(singbox_manager.CONFIG_PATH.read_text(encoding="utf-8"))
    assert cfg["route"]["final"] == "direct"
    assert any("chrome.exe" in x.get("process_name", []) and x.get("outbound") == "auto" for x in cfg["route"]["rules"])
    assert app_routing.load().mode == app_routing.MODE_ONLY
    ctl.set_routing(app_routing.RoutingSettings())
    _drain(ctl, lambda e: e == ("vpn", "on"), timeout=20)
    assert json.loads(singbox_manager.CONFIG_PATH.read_text(encoding="utf-8"))["route"]["final"] == "auto"
    print("OK: маршрутизация по приложениям применяется на лету и сохраняется")

    # закрепление прокси при включённом VPN — сразу в конфиг, через переключатель
    good_addr = next(r.proxy.address for r in ctl.results if r.working)
    ctl.pin_proxy(good_addr)
    _drain(ctl, lambda e: e == ("vpn", "on"), timeout=20)
    cfg = json.loads(singbox_manager.CONFIG_PATH.read_text(encoding="utf-8"))
    assert cfg["route"]["final"] == "pinned" and ctl._pin_tag
    assert app_settings.load().pinned_address == good_addr
    print("OK: закрепление прокси применяется на лету и сохраняется")

    # 3a) обновление списка при включённом VPN — VPN не выключается,
    #     а в конце перезапускается с новым списком
    ctl.refresh(timeout=1.5)
    events = []
    seen = {"busy_done": False, "restarted": False}

    def until(e):
        events.append(e)
        if e == ("busy", False):
            seen["busy_done"] = True
        states = [x[1] for x in events if x[0] == "vpn"]
        if states[-2:] == ["connecting", "on"]:
            seen["restarted"] = True
        return seen["busy_done"] and seen["restarted"]

    _drain(ctl, until, timeout=40)
    vpn_states = [e[1] for e in events if e[0] == "vpn"]
    assert vpn_states[-2:] == ["connecting", "on"], vpn_states
    assert not any(e[0] == "log" and "Временно отключаю" in e[1] for e in events)
    print("OK: обновление при включённом VPN: проверка мимо VPN, затем VPN перезапущен с новым списком")

    # 3b) автоподбор: группа «умерла» -> берём живые из запаса и перезапускаем
    extra_ports = [_start_fake_network()[0] for _ in range(3)]
    reserve = [CheckResult(Proxy("127.0.0.1", p, ProxyType.SOCKS5, country_code="DE"), True, latency_ms=50) for p in extra_ports]
    ctl.results = ctl.results + reserve
    restarts = []
    ctl._restart_vpn_blocking = lambda: restarts.append(1)
    ctl_mod.fetch_group_health = lambda api_addr=None: (0, 1, 1)
    ctl.HEAL_MIN_INTERVAL = 0
    ctl._submit(ctl._maybe_heal()).result(timeout=30)
    assert not restarts, "после одной плохой проверки рано"
    ctl._submit(ctl._maybe_heal()).result(timeout=30)
    assert restarts == [1], restarts
    group = set(ctl._current_group)
    assert all(not r.working for r in ctl.results if r.proxy.address in group)
    assert sum(1 for r in ctl.results if r.working) >= 3
    print("OK: автоподбор — после двух плохих проверок подряд замена найдена в запасе, VPN перезапущен")

    # 3c) фоновое обновление: VPN без нужды не перезапускается (это рвёт звонки),
    #     сторонний VPN — не спрашиваем, а откладываем
    restarts.clear()
    ctl_mod.fetch_group_health = lambda api_addr=None: (3, 3, 3)  # текущие прокси отвечают
    ctl.refresh(timeout=1.5, background=True)
    events = _drain(ctl, lambda e: e == ("busy", False), timeout=40)
    assert not restarts and any(e[0] == "log" and "не перезапускаю" in e[1] for e in events)
    ctl_mod.fetch_group_health = lambda api_addr=None: (0, 3, 3)  # сдали — перезапуск нужен
    ctl.refresh(timeout=1.5, background=True)
    _drain(ctl, lambda e: e == ("busy", False), timeout=40)
    assert restarts == [1], restarts
    print("OK: фоновое обновление перезапускает VPN, только если его прокси сдали")
    netpath.detect_external_vpn = lambda: ["Ethernet 3 | WireGuard Tunnel"]
    ctl.refresh(timeout=1.5, background=True)
    events = _drain(ctl, lambda e: e == ("busy", False), timeout=20)
    assert not any(e[0] in ("ask", "error") for e in events) and not ctl._auto_refresh_due(time.time())
    netpath.detect_external_vpn = lambda: []
    print("OK: в фоне при стороннем VPN — без вопросов и окон, повтор через полчаса")
    del ctl._restart_vpn_blocking

    ctl.disconnect_vpn()
    _drain(ctl, lambda e: e == ("vpn", "off"))
    assert ctl.vpn_state == "off"
    print("OK: VPN отключается")

    _test_pin_failover(ctl)
    _test_auto_refresh_and_startup(ctl)

    # 3) неожиданное падение sing-box -> ошибка в GUI
    crash_exe = _fake_singbox("sing-box-crash", "FATAL bad config", 1)
    singbox_manager.find_singbox = lambda: crash_exe
    ctl.connect_vpn()
    events = _drain(ctl, lambda e: e[0] == "error")
    errs = [e[1] for e in events if e[0] == "error"]; print("errors:", errs)
    assert any("кодом 1" in m for m in errs), errs
    _drain(ctl, lambda e: e == ("vpn", "off"))
    print("OK: падение sing-box показывается пользователю как ошибка")

    ctl.shutdown()
    _test_fetch_vpn_status()
    print("\nВсе тесты controller.py прошли.")
    os._exit(0)


if __name__ == "__main__":
    main()

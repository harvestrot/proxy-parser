"""Мост к узлам VLESS / VMess / Trojan / Shadowsocks для проверки.

Проверщик (checker.py) и замер скорости (quality.py) говорят только на
SOCKS/HTTP. На время проверки запускается отдельный sing-box без TUN (прав
администратора не нужно): каждому узлу — свой вход SOCKS5 на 127.0.0.1, и
трафик этого входа уходит в узел. connect_via (upstream.py) для узла
подключается к его входу — и вся проверка (HTTPS, сертификаты, подмена по IP,
скорость) работает для узлов так же, как для обычных прокси.

Мост живёт, пока идёт проверка (``async with serve(proxies)``); вложенные
запуски поднимают только те узлы, которых ещё нет в мосте.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import pathlib
import re
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Callable

from . import nodes, singbox_manager
from .models import Proxy

log = logging.getLogger(__name__)

START_TIMEOUT_S = 15.0
MAX_INVALID = 50  # столько узлов, не принятых sing-box, выбрасываем по одному — дальше сдаёмся

_NO_WINDOW = subprocess.CREATE_NO_WINDOW if singbox_manager.IS_WINDOWS else 0
_ports: dict[tuple[str, str, int], int] = {}  # (тип, хост, порт) -> локальный порт SOCKS5


def _key(p: Proxy) -> tuple[str, str, int]:
    return p.type.value, p.host, p.port


def local_port(p: Proxy) -> int | None:
    """Локальный SOCKS5 узла, если мост для него запущен."""
    return _ports.get(_key(p))


def _free_ports(n: int) -> list[int]:
    socks, ports = [], []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            s.close()
    return ports


def build_config(items: list[tuple[Proxy, int]]) -> dict:
    """Конфиг моста: узел i — вход in{i} (SOCKS5/HTTP на 127.0.0.1) -> выход n{i}."""
    inbounds, outbounds, rules = [], [], []
    for i, (proxy, port) in enumerate(items):
        inbounds.append({"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1", "listen_port": port})
        outbounds.append({**nodes.outbound(proxy), "tag": f"n{i}"})
        rules.append({"inbound": [f"in{i}"], "outbound": f"n{i}"})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": "error"},
        # адреса серверов-доменов — системным DNS (как и быстрый отсев)
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct", "default_domain_resolver": "local"},
    }


_BAD_OUTBOUND_RE = re.compile(r"outbounds?\[(\d+)\]")


def _drop_invalid(exe: pathlib.Path, items: list[tuple[Proxy, int]], cfg: pathlib.Path) -> list[tuple[Proxy, int]]:
    """Убрать узлы, которые sing-box не принимает (``sing-box check`` называет
    номер первого плохого outbound) — иначе не запустится весь мост."""
    items = list(items)
    for _ in range(MAX_INVALID):
        cfg.write_text(json.dumps(build_config(items), ensure_ascii=False), encoding="utf-8")
        res = subprocess.run([str(exe), "check", "-c", str(cfg)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", creationflags=_NO_WINDOW)
        if res.returncode == 0:
            return items
        m = _BAD_OUTBOUND_RE.search(res.stderr + res.stdout)
        if m is None or int(m.group(1)) >= len(items):
            log.warning("Мост к узлам: sing-box не принял конфиг (%s) — узлы не проверяются",
                        (res.stderr or res.stdout).strip()[-200:])
            return []
        bad = items.pop(int(m.group(1)))
        log.debug("Узел %s не принят sing-box — пропускаю", bad[0].address)
    log.warning("Мост к узлам: слишком много узлов, которые sing-box не принимает — узлы не проверяются")
    return []


def _wait_listening(port: int, proc: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def _start(exe: pathlib.Path, nodes_to_start: list[Proxy]) -> tuple[subprocess.Popen, pathlib.Path, list] | None:
    folder = pathlib.Path(tempfile.mkdtemp(prefix="proxyparser-bridge-"))
    cfg = folder / "bridge.json"
    items = _drop_invalid(exe, list(zip(nodes_to_start, _free_ports(len(nodes_to_start)))), cfg)
    if not items:
        shutil.rmtree(folder, ignore_errors=True)
        return None
    proc = subprocess.Popen([str(exe), "run", "-c", str(cfg)], cwd=str(exe.parent), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=_NO_WINDOW)
    if not _wait_listening(items[-1][1], proc, START_TIMEOUT_S):
        log.warning("Мост к узлам не запустился — узлы не проверяются")
        _stop(proc, folder)
        return None
    return proc, folder, items


def _stop(proc: subprocess.Popen, folder: pathlib.Path) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(folder, ignore_errors=True)


SingboxFinder = Callable[[], "pathlib.Path | None"]


@contextlib.asynccontextmanager
async def serve(proxies: list[Proxy], find: SingboxFinder | None = None):
    """Пока открыт контекст, узлы из ``proxies`` доступны через local_port().
    Без sing-box (не скачался) узлы просто не проверятся — остальное работает."""
    pending = {_key(p): p for p in proxies if p.type.is_node and p.link and _key(p) not in _ports}
    if not pending:
        yield
        return
    exe = await asyncio.to_thread(find or singbox_manager.ensure_singbox)
    started = await asyncio.to_thread(_start, exe, list(pending.values())) if exe else None
    if started is None:
        yield
        return
    proc, folder, items = started
    for proxy, port in items:
        _ports[_key(proxy)] = port
    try:
        yield
    finally:
        for proxy, _port in items:
            _ports.pop(_key(proxy), None)
        await asyncio.to_thread(_stop, proc, folder)

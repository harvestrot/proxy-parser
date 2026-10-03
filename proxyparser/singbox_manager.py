"""Управление sing-box из Python: найти/скачать бинарник, запустить, остановить.

Нужен GUI, чтобы пользователю вообще не трогать PowerShell-скрипты.
"""
from __future__ import annotations

import io
import os
import pathlib
import re
import subprocess
import sys
import threading
import zipfile
from typing import Callable

from . import paths

PROJECT_ROOT = paths.APP_DIR
VPN_DIR = PROJECT_ROOT / "vpn"
BIN_DIR = VPN_DIR / "bin"
CONFIG_PATH = VPN_DIR / "config.json"

# Версия sing-box закреплена: конфиг проверен именно на ней, а у sing-box между
# версиями меняется формат конфига — «последняя» однажды сломала бы VPN у всех.
# Хеш — чтобы с правами администратора запускался ровно проверенный файл.
SINGBOX_VERSION = "1.14.2"
SINGBOX_URL = (f"https://github.com/SagerNet/sing-box/releases/download/v{SINGBOX_VERSION}/"
               f"sing-box-{SINGBOX_VERSION}-windows-amd64.zip")
SINGBOX_ZIP_SHA256 = "c2d8bfff918755808781dfdeeb8581b6c91eb3a243d9a7b55483cfc0c0684d32"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

IS_WINDOWS = sys.platform == "win32"
RELAUNCHED_ARG = "--relaunched"


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Перезапустить программу с правами администратора (покажется окно UAC).
    Возвращает True, если запуск принят системой."""
    if not IS_WINDOWS:
        return False
    import ctypes

    exe, args = paths.launch_command()
    # --relaunched: новая копия подождёт, пока эта закроется (одна копия программы)
    params = " ".join([f'"{a}"' for a in args] + [RELAUNCHED_ARG])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, str(PROJECT_ROOT), 1)
    return rc > 32


def own_process_paths() -> list[str]:
    """Пути к исполняемым файлам программы. Нужны для правила sing-box
    «трафик программы — мимо VPN». Собранный exe — это он сам. Из исходников:
    на Windows python.exe из venv — лишь «пускалка», реальные соединения
    делает базовый интерпретатор, поэтому добавляем оба (и python.exe, и
    pythonw.exe рядом с ними)."""
    # sing-box тоже: мост к узлам (bridge.py) — отдельный его процесс, и при
    # включённом VPN проверка узлов иначе пошла бы через сам VPN (свой же
    # трафик VPN-процесс sing-box в туннель не заворачивает — правило его не задевает)
    singbox = find_singbox()
    extra = [str(singbox)] if singbox else []
    if paths.FROZEN:
        return [sys.executable] + extra
    exes = {sys.executable, getattr(sys, "_base_executable", None) or sys.executable}
    out: list[str] = []
    for exe in exes:
        folder = pathlib.Path(exe).parent
        names = ("python.exe", "pythonw.exe") if IS_WINDOWS else (pathlib.Path(exe).name,)
        for name in names:
            candidate = folder / name
            if candidate.exists():
                out.append(str(candidate))
    return (sorted(set(out)) or [sys.executable]) + extra


def find_singbox() -> pathlib.Path | None:
    """vpn/bin/sing-box.exe, иначе любой sing-box.exe в подпапках проекта
    (например, уже скачанный вручную sing-box-1.14.2-windows-amd64/)."""
    exe_name = "sing-box.exe" if IS_WINDOWS else "sing-box"
    preferred = BIN_DIR / exe_name
    if preferred.exists():
        return preferred
    for candidate in sorted(PROJECT_ROOT.glob(f"*/{exe_name}")):
        return candidate
    for candidate in sorted(PROJECT_ROOT.glob(f"*/*/{exe_name}")):
        if ".venv" not in candidate.parts:
            return candidate
    return None


def download_singbox(log: Callable[[str], None] = print) -> pathlib.Path:
    """Скачать sing-box (закреплённую версию) для Windows amd64 в vpn/bin/."""
    import hashlib

    import requests

    log(f"Скачиваю sing-box {SINGBOX_VERSION} с GitHub (~30 МБ, один раз)...")
    resp = requests.get(SINGBOX_URL, timeout=180, headers={"User-Agent": "proxy-parser"})
    resp.raise_for_status()
    digest = hashlib.sha256(resp.content).hexdigest()
    if digest != SINGBOX_ZIP_SHA256:
        raise RuntimeError(
            f"Скачанный архив sing-box не совпал с проверенным (SHA-256 {digest[:16]}…) — не запускаю. "
            f"Скачай вручную: {SINGBOX_URL} и распакуй в папку программы"
        )

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        for member in zf.namelist():
            name = pathlib.PurePosixPath(member).name
            if name in ("sing-box.exe", "libcronet.dll"):
                (BIN_DIR / name).write_bytes(zf.read(member))
    exe = BIN_DIR / "sing-box.exe"
    if not exe.exists():
        raise RuntimeError("В архиве не нашёлся sing-box.exe")
    log(f"sing-box {SINGBOX_VERSION} установлен в {exe}")
    return exe


def ensure_singbox(log: Callable[[str], None] | None = None) -> pathlib.Path | None:
    """sing-box из папки программы, а если его нет — скачать (один раз).
    None — не нашёлся и не скачался (без интернета, не тот архив…)."""
    exe = find_singbox()
    if exe is not None:
        return exe
    import logging

    say = log or logging.getLogger(__name__).info
    try:
        return download_singbox(log=say)
    except Exception as exc:  # noqa: BLE001 — без sing-box просто не будет узлов/VPN
        say(f"sing-box не скачался: {exc}")
        return None


class SingBoxProcess:
    """Обёртка над процессом sing-box: запуск без окна консоли, построчная
    передача лога наружу, остановка."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(
        self,
        exe: pathlib.Path,
        config: pathlib.Path,
        on_line: Callable[[str], None],
        on_exit: Callable[[int], None],
    ) -> None:
        if self.running:
            raise RuntimeError("sing-box уже запущен")
        flags = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
        self._proc = subprocess.Popen(
            [str(exe), "run", "-c", str(config)],
            cwd=str(exe.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=flags,
        )
        proc = self._proc

        def _pump() -> None:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = _ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
                if line:
                    on_line(line)
            on_exit(proc.wait())

        self._reader = threading.Thread(target=_pump, daemon=True)
        self._reader.start()

    def stop(self, timeout: float = 5.0) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        # Wintun-адаптер и его маршруты удаляются системой вместе с
        # процессом, так что terminate безопасен для сети.
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()

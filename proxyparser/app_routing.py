"""Маршрутизация по приложениям: какие программы идут через прокси.

Режимы (как раздельное туннелирование в обычных VPN-клиентах):
  * "all"    — весь трафик компьютера через прокси (как раньше);
  * "only"   — через прокси только выбранные приложения, остальное напрямую;
  * "except" — через прокси всё, кроме выбранных приложений.

Приложение задаётся именами его процессов (``chrome.exe``): sing-box
сопоставляет соединение с процессом. Имя, а не полный путь, — чтобы правило
не ломалось при обновлении программы (у Discord, например, путь меняется с
каждой версией). У некоторых программ сеть идёт из нескольких процессов
(Steam — ещё и steamwebhelper.exe) — для известных они добавляются сами.

Настройки — в routing.json в папке программы.
"""
from __future__ import annotations

import json
import logging
import pathlib
import subprocess
import sys
from dataclasses import dataclass, field

from . import storage
from .paths import APP_DIR

log = logging.getLogger(__name__)

ROUTING_FILE = APP_DIR / "routing.json"

MODE_ALL, MODE_ONLY, MODE_EXCEPT = "all", "only", "except"
MODES = {
    MODE_ALL: "Весь трафик",
    MODE_ONLY: "Только выбранные приложения",
    MODE_EXCEPT: "Всё, кроме выбранных",
}


@dataclass
class AppEntry:
    title: str              # как показать человеку: «Google Chrome»
    processes: list[str]    # имена процессов: ["chrome.exe"]

    def key(self) -> frozenset[str]:
        return frozenset(p.lower() for p in self.processes)


# Популярные программы — для быстрого добавления (даже если сейчас не запущены)
# и чтобы у известных подтянуть все их сетевые процессы.
KNOWN_APPS: list[AppEntry] = [
    AppEntry("Google Chrome", ["chrome.exe"]),
    AppEntry("Яндекс Браузер", ["browser.exe"]),
    AppEntry("Microsoft Edge", ["msedge.exe"]),
    AppEntry("Mozilla Firefox", ["firefox.exe"]),
    AppEntry("Opera", ["opera.exe"]),
    AppEntry("Discord", ["Discord.exe"]),
    AppEntry("Telegram", ["Telegram.exe"]),
    AppEntry("Spotify", ["Spotify.exe"]),
    AppEntry("Steam", ["steam.exe", "steamwebhelper.exe"]),
    AppEntry("Epic Games", ["EpicGamesLauncher.exe", "EpicWebHelper.exe"]),
]


@dataclass
class RoutingSettings:
    mode: str = MODE_ALL
    apps: list[AppEntry] = field(default_factory=list)

    def process_names(self) -> list[str]:
        """Все имена процессов для правила sing-box. Плюс вариант в нижнем
        регистре: Windows к регистру не чувствительна, а сравнение — точное."""
        out: dict[str, None] = {}
        for app in self.apps:
            for p in app.processes:
                out.setdefault(p, None)
                out.setdefault(p.lower(), None)
        return list(out)

    def effective_mode(self) -> str:
        # «кроме» с пустым списком — то же, что «весь трафик»
        if self.mode == MODE_EXCEPT and not self.apps:
            return MODE_ALL
        return self.mode

    def describe(self) -> str:
        titles = ", ".join(a.title for a in self.apps)
        if self.mode == MODE_ONLY:
            return f"Через прокси: {titles}" if self.apps else "Приложения не выбраны — весь трафик идёт напрямую"
        if self.mode == MODE_EXCEPT and self.apps:
            return f"Мимо прокси: {titles}"
        return "Весь трафик компьютера через прокси"

    def to_dict(self) -> dict:
        return {"mode": self.mode, "apps": [{"title": a.title, "processes": a.processes} for a in self.apps]}


def from_dict(data: dict) -> RoutingSettings:
    mode = data.get("mode") if data.get("mode") in MODES else MODE_ALL
    apps: list[AppEntry] = []
    seen: set[frozenset[str]] = set()
    for raw in data.get("apps") or []:
        if not isinstance(raw, dict):
            continue
        procs = [str(p).strip() for p in raw.get("processes") or [] if str(p).strip()]
        if not procs:
            continue
        app = AppEntry(str(raw.get("title") or procs[0]), procs)
        if app.key() not in seen:
            seen.add(app.key())
            apps.append(app)
    return RoutingSettings(mode, apps)


def load(path: pathlib.Path | None = None) -> RoutingSettings:
    path = path or ROUTING_FILE
    if not path.exists():
        return RoutingSettings()
    return from_dict(storage.read_json(path) or {})


def save(settings: RoutingSettings, path: pathlib.Path | None = None) -> None:
    storage.write_atomic(path or ROUTING_FILE, json.dumps(settings.to_dict(), ensure_ascii=False, indent=2))


def app_for_exe(exe_name: str, title: str | None = None) -> AppEntry:
    """Запись для .exe: у известных программ — с их дополнительными процессами."""
    for known in KNOWN_APPS:
        if exe_name.lower() in known.key():
            # имя — как в системе (регистр важен), остальные процессы — из списка
            return AppEntry(known.title, [exe_name] + [p for p in known.processes if p.lower() != exe_name.lower()])
    return AppEntry(title or pathlib.Path(exe_name).stem, [exe_name])


# ------------------------------------------------------------ запущенные программы

@dataclass
class RunningApp:
    title: str
    exe: str
    path: str
    windowed: bool  # есть окно — скорее всего, это то, что человек и ищет


_PS_LIST = (
    "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
    "Get-Process | Where-Object { $_.Path } | ForEach-Object { "
    "  $d = ''; try { $d = (Get-Item -LiteralPath $_.Path).VersionInfo.FileDescription } catch {} ; "
    "  [pscustomobject]@{ p = $_.Path; d = $d; w = [int]($_.MainWindowHandle -ne 0) } "
    "} | ConvertTo-Json -Compress"
)


def parse_running_apps(text: str, skip_dirs: tuple[str, ...] = ()) -> list[RunningApp]:
    """Разобрать вывод PowerShell: по одному на .exe, системное и своё — мимо;
    сначала программы с окнами, внутри — по названию."""
    try:
        data = json.loads(text or "[]")
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    skip = tuple(d.lower().rstrip("\\") + "\\" for d in skip_dirs if d)
    apps: dict[str, RunningApp] = {}
    for item in data:
        path = str(item.get("p") or "")
        if not path or path.lower().startswith(skip):
            continue
        exe = pathlib.PureWindowsPath(path).name
        title = str(item.get("d") or "").strip() or pathlib.PureWindowsPath(path).stem
        prev = apps.get(exe.lower())
        windowed = bool(item.get("w"))
        if prev is None:
            apps[exe.lower()] = RunningApp(title, exe, path, windowed)
        elif windowed and not prev.windowed:
            prev.windowed = True
    return sorted(apps.values(), key=lambda a: (not a.windowed, a.title.lower()))


def list_running_apps() -> list[RunningApp]:
    """Запущенные программы (Windows). Медленно (~1–2 с) — вызывать не из окна."""
    if sys.platform != "win32":
        return []
    import os

    try:
        raw = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_LIST],
            capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
        ).stdout
    except Exception as exc:  # noqa: BLE001
        log.warning("Не удалось получить список программ: %s", exc)
        return []
    own = pathlib.Path(sys.executable).parent
    skip = (os.environ.get("SystemRoot", r"C:\Windows"), str(own), str(pathlib.Path(sys.base_prefix)))
    apps = parse_running_apps(raw.decode("utf-8", errors="replace"), skip)
    return [a for a in apps if a.exe.lower() != "sing-box.exe"]

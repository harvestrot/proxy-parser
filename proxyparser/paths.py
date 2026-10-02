"""Где лежат файлы программы — в исходниках и в собранном exe одинаково.

Собранный в один файл exe (PyInstaller) при каждом запуске распаковывается
во временную папку, и ``__file__`` указывает туда. Данные программы
(results/, vpn/, sources.json, settings.json, routing.json) должны жить
рядом с самим exe, иначе терялись бы при каждом закрытии.
"""
from __future__ import annotations

import pathlib
import sys

FROZEN = bool(getattr(sys, "frozen", False))  # запущен собранный exe

# папка программы: рядом с exe — или корень проекта при запуске из исходников
APP_DIR = pathlib.Path(sys.executable).resolve().parent if FROZEN else pathlib.Path(__file__).resolve().parents[1]
GUI_SCRIPT = APP_DIR / "gui.py"  # только для запуска из исходников


def launch_command() -> tuple[str, list[str]]:
    """Чем запускать окно программы заново (перезапуск от администратора,
    автозапуск): (исполняемый файл, аргументы до наших ключей)."""
    if FROZEN:
        return sys.executable, []
    exe = pathlib.Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")  # без чёрного окна консоли
    return str(pythonw if pythonw.exists() else exe), [str(GUI_SCRIPT)]

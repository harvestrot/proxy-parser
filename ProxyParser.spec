# Сборка Proxy Parser в один exe (PyInstaller). Запуск: build.bat
# -*- mode: python ; coding: utf-8 -*-
import re
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (FixedFileInfo, StringFileInfo, StringStruct, StringTable,
                                                 VarFileInfo, VarStruct, VSVersionInfo)

ROOT = Path(SPECPATH)
VERSION = re.search(r'__version__ = "([^"]+)"', (ROOT / "proxyparser" / "__init__.py").read_text()).group(1)
NUMS = tuple(int(x) for x in VERSION.split(".")) + (0,) * (4 - len(VERSION.split(".")))

# Свойства файла (ПКМ → Свойства → Подробно): exe без них чаще пугает антивирусы
version_info = VSVersionInfo(
    ffi=FixedFileInfo(filevers=NUMS, prodvers=NUMS),
    kids=[
        StringFileInfo([StringTable("041904B0", [
            StringStruct("ProductName", "Proxy Parser"),
            StringStruct("FileDescription", "Proxy Parser — VPN через бесплатные прокси"),
            StringStruct("FileVersion", VERSION),
            StringStruct("ProductVersion", VERSION),
            StringStruct("OriginalFilename", "ProxyParser.exe"),
            StringStruct("LegalCopyright", "MIT License"),
        ])]),
        VarFileInfo([VarStruct("Translation", [0x0419, 1200])]),
    ],
)

a = Analysis(
    [str(ROOT / "gui.py")],
    pathex=[str(ROOT)],
    hiddenimports=["pystray._win32", "PIL.ImageTk"],  # трей и значок окна грузятся динамически
    excludes=["pytest", "unittest", "pydoc", "doctest", "lib2to3", "tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ProxyParser",
    icon=str(ROOT / "assets" / "icon.ico"),
    version=version_info,
    console=False,   # окно без чёрной консоли
    upx=False,       # UPX-сжатие часто вызывает ложные срабатывания антивирусов
    runtime_tmpdir=None,
)

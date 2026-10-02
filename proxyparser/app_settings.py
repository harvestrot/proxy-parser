"""Настройки программы — settings.json в папке программы.

Маршрутизация по приложениям лежит отдельно (routing.json, см. app_routing).
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import asdict, dataclass, field, fields

from . import storage
from .paths import APP_DIR

SETTINGS_FILE = APP_DIR / "settings.json"

AUTO_REFRESH_CHOICES = (0, 1, 2, 3, 6, 12)  # часы; 0 — выключено

# Быстрый выбор «только Европа» (ISO-коды) — для фильтра стран.
EUROPE = {
    "AL", "AD", "AT", "BA", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR",
    "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT", "NL", "NO", "PL",
    "PT", "RO", "RS", "SE", "SI", "SK", "SM", "UA",
}


@dataclass
class AppSettings:
    auto_connect: bool = False        # подключать VPN сразу после запуска программы
    close_to_tray: bool = True        # крестик окна — свернуть в трей, а не выйти
    auto_refresh_hours: int = 3       # фоновое обновление списка; 0 — выключено
    pinned: dict | None = None        # закреплённый прокси: {"address": "1.2.3.4:1080", "type": "SOCKS5"}
    countries: list[str] = field(default_factory=list)  # разрешённые страны (ISO); пусто — любые

    @property
    def pinned_address(self) -> str | None:
        return (self.pinned or {}).get("address")


def from_dict(data: dict) -> AppSettings:
    s = AppSettings()
    known = {f.name for f in fields(AppSettings)}
    for key, value in data.items():
        if key in known:
            setattr(s, key, value)
    # защита от ручной правки файла
    s.auto_connect = bool(s.auto_connect)
    s.close_to_tray = bool(s.close_to_tray)
    s.auto_refresh_hours = s.auto_refresh_hours if s.auto_refresh_hours in AUTO_REFRESH_CHOICES else 3
    if not (isinstance(s.pinned, dict) and isinstance(s.pinned.get("address"), str)):
        s.pinned = None
    s.countries = sorted({str(c).upper() for c in s.countries or [] if isinstance(c, str) and len(c) == 2})
    return s


def load(path: pathlib.Path | None = None) -> AppSettings:
    path = path or SETTINGS_FILE
    if not path.exists():
        return AppSettings()
    return from_dict(storage.read_json(path) or {})


def save(settings: AppSettings, path: pathlib.Path | None = None) -> None:
    storage.write_atomic(path or SETTINGS_FILE, json.dumps(asdict(settings), ensure_ascii=False, indent=2))

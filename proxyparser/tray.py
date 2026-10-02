"""Значок в трее (области уведомлений Windows).

pystray работает в своём потоке; нажатия в меню не трогают tkinter напрямую
(из чужого потока нельзя), а кладутся в очередь ``actions`` — окно забирает
их само. Без pystray/Pillow программа работает, просто без трея.
"""
from __future__ import annotations

import logging
import queue
import threading

log = logging.getLogger(__name__)

try:  # pragma: no cover — зависит от установленных пакетов
    import pystray
    from PIL import Image, ImageDraw
    AVAILABLE = True
except Exception:  # noqa: BLE001
    AVAILABLE = False

STATE_COLORS = {"off": (150, 150, 150), "connecting": (215, 155, 0), "on": (46, 157, 74)}


def make_icon(state: str, size: int = 64):
    """Круглый значок цвета состояния VPN с белой «П» (Proxy) внутри."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, size - 2, size - 2), fill=STATE_COLORS.get(state, STATE_COLORS["off"]) + (255,))
    # «П» из трёх прямоугольников — не зависим от шрифтов
    w, top, bottom = size // 9, size * 27 // 100, size * 73 // 100
    left, right = size * 30 // 100, size * 70 // 100
    d.rectangle((left, top, right, top + w), fill="white")
    d.rectangle((left, top, left + w, bottom), fill="white")
    d.rectangle((right - w, top, right, bottom), fill="white")
    return img


class Tray:
    """Действия меню → очередь ``actions``: "show", "toggle_vpn", "refresh", "quit"."""

    def __init__(self, title: str) -> None:
        self.actions: "queue.Queue[str]" = queue.Queue()
        self._state = "off"
        self._busy = False
        self._icon = None
        if not AVAILABLE:
            return
        menu = pystray.Menu(
            pystray.MenuItem("Открыть", lambda: self.actions.put("show"), default=True),
            pystray.MenuItem(lambda _i: "Отключить VPN" if self._state == "on" else "Подключить VPN",
                             lambda: self.actions.put("toggle_vpn"),
                             enabled=lambda _i: self._state != "connecting"),
            pystray.MenuItem("Обновить список", lambda: self.actions.put("refresh"),
                             enabled=lambda _i: not self._busy),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", lambda: self.actions.put("quit")),
        )
        self._icon = pystray.Icon("proxyparser", make_icon("off"), title, menu)
        threading.Thread(target=self._run, daemon=True, name="tray").start()

    def _run(self) -> None:
        try:
            self._icon.run()
        except Exception:  # noqa: BLE001
            log.exception("Значок в трее не запустился")
            self._icon = None

    @property
    def available(self) -> bool:
        return self._icon is not None

    def set_state(self, state: str, tooltip: str | None = None) -> None:
        self._state = state
        if self._icon is not None:
            self._icon.icon = make_icon(state)
            if tooltip:
                self._icon.title = tooltip[:127]  # у Windows ограничение длины подсказки
            self._icon.update_menu()

    def set_busy(self, busy: bool) -> None:
        self._busy = busy
        if self._icon is not None:
            self._icon.update_menu()

    def set_tooltip(self, text: str) -> None:
        if self._icon is not None:
            self._icon.title = text[:127]

    def notify(self, message: str, title: str = "Proxy Parser") -> None:
        if self._icon is not None:
            try:
                self._icon.notify(message, title)
            except Exception:  # noqa: BLE001 — уведомления не критичны
                pass

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:  # noqa: BLE001
                pass

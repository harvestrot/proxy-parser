"""Одна копия программы: вторая не запускается, а показывает окно первой.

С автозапуском программа живёт в трее, и легко запустить её ещё раз — две
копии стали бы одновременно управлять VPN. Первая копия слушает локальный
порт; вторая, не сумев его занять, шлёт туда «покажись» и закрывается.
"""
from __future__ import annotations

import socket
import threading
import time
from typing import Callable

PORT = 48213
SHOW = b"show"


def acquire(wait_s: float = 0.0, port: int = PORT) -> socket.socket | None:
    """Занять порт (= стать единственной копией). ``wait_s`` — сколько ждать,
    пока его освободит закрывающаяся прежняя копия (перезапуск от
    администратора). None — уже запущена другая копия."""
    deadline = time.monotonic() + wait_s
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: никто не «перехватит» порт
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            sock.bind(("127.0.0.1", port))
            sock.listen(4)
            return sock
        except OSError:
            sock.close()
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.3)


def notify_existing(port: int = PORT) -> bool:
    """Попросить уже запущенную копию показать окно."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.sendall(SHOW)
        return True
    except OSError:
        return False


def serve(sock: socket.socket, on_show: Callable[[], None]) -> None:
    """В фоне ждать «покажись» от новых копий."""
    def loop() -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return  # сокет закрыт — программа выходит
            with conn:
                try:
                    if conn.recv(16).startswith(SHOW):
                        on_show()
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True, name="single-instance").start()

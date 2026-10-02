"""Proxy Parser — графический интерфейс.

Запуск: двойной клик по «Запустить ProxyParser.bat» (он сам создаст
окружение и поставит зависимости) или ``pythonw gui.py``.
"""
from __future__ import annotations

import dataclasses
import os
import pathlib
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from proxyparser import (__version__, app_routing, app_settings, autostart, single_instance,  # noqa: E402
                         singbox_manager, sources_config, tray)
from proxyparser.controller import AppController  # noqa: E402
from proxyparser.models import CheckResult  # noqa: E402

APP_TITLE = "Proxy Parser"

VPN_LABELS = {
    "off": ("●  VPN отключён", "#9a9a9a", "Подключить VPN"),
    "connecting": ("●  Подключаюсь...", "#d79b00", "Подождите..."),
    "on": ("●  VPN подключён", "#2e9d4a", "Отключить VPN"),
}


class App:
    def __init__(self, root: tk.Tk, start_hidden: bool = False) -> None:
        self.root = root
        self.ctl = AppController()
        self.tray = tray.Tray(APP_TITLE)
        self._hidden = False
        self._closed = False
        self._tray_hint_shown = False

        admin_suffix = " (администратор)" if singbox_manager.is_admin() else ""
        root.title(f"{APP_TITLE} {__version__}{admin_suffix}")
        self._set_window_icon()
        root.geometry("1080x800")
        root.minsize(760, 640)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Big.TButton", font=("Segoe UI", 11, "bold"), padding=(16, 8))
        style.configure("Status.TLabel", font=("Segoe UI", 11, "bold"))

        self._build_connection_panel()
        self._build_proxy_panel()
        self._build_log_panel()

        self._render_results(self.ctl.results)
        self._apply_vpn_state("off")
        if not self.ctl.results:
            self.status_var.set("Список прокси пуст — нажми «Обновить список»")

        if start_hidden:  # автозапуск с Windows: сразу в трей (без трея — свёрнутым)
            self.hide_window() if self.tray.available else root.iconify()
        self.root.after(100, self._poll_events)
        self.root.after(500, self.ctl.startup)  # автоподключение VPN, если включено

    # ------------------------------------------------------------ окно и трей

    def _set_window_icon(self) -> None:
        """Значок окна — тот же, что в трее (рисуется Pillow, файл не нужен)."""
        if not tray.AVAILABLE:
            return
        try:
            from PIL import ImageTk

            self._icon_image = ImageTk.PhotoImage(tray.make_icon("on", 64))  # держим ссылку — иначе исчезнет
            self.root.iconphoto(True, self._icon_image)
        except Exception:  # noqa: BLE001 — значок не критичен
            pass

    def hide_window(self) -> None:
        self.root.withdraw()
        self._hidden = True

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self._hidden = False

    def quit(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.ctl.shutdown()
        finally:
            self.tray.stop()
            self.root.destroy()

    def _handle_tray_action(self, action: str) -> None:
        if action == "show":
            self.show_window()
        elif action == "toggle_vpn":
            if not singbox_manager.is_admin() or not self.ctl.results:
                self.show_window()  # дальше будут вопросы/подсказки — их надо видеть
            self.on_vpn_click()
        elif action == "refresh":
            self.on_refresh_click()
        elif action == "quit":
            self.quit()

    # ------------------------------------------------------------ layout

    def _build_connection_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Подключение", padding=12)
        frame.pack(fill="x", padx=12, pady=(12, 6))

        # VPN
        self.vpn_status = ttk.Label(frame, style="Status.TLabel")
        self.vpn_status.grid(row=0, column=0, sticky="w")
        right = ttk.Frame(frame)
        right.grid(row=0, column=1, sticky="e", padx=(12, 0))
        ttk.Button(right, text="⚙ Настройки…", command=self.on_settings_click).pack(side="left", padx=(0, 10))
        self.vpn_button = ttk.Button(right, style="Big.TButton", command=self.on_vpn_click)
        self.vpn_button.pack(side="left")
        self.vpn_info = ttk.Label(frame, text="", wraplength=640)
        self.vpn_info.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # маршрутизация по приложениям
        routing = ttk.Frame(frame)
        routing.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(routing, text="Маршрутизация:").pack(side="left")
        self.routing_label = ttk.Label(routing, text="", font=("Segoe UI", 9, "bold"))
        self.routing_label.pack(side="left", padx=(6, 0))
        ttk.Button(routing, text="Настроить…", command=self.on_routing_click).pack(side="left", padx=(10, 0))
        self._show_routing()

        # какой прокси и из каких стран
        prefs = ttk.Frame(frame)
        prefs.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        ttk.Label(prefs, text="Прокси:").pack(side="left")
        self.pin_label = ttk.Label(prefs, text="", font=("Segoe UI", 9, "bold"))
        self.pin_label.pack(side="left", padx=(6, 0))
        self.unpin_button = ttk.Button(prefs, text="Открепить", command=lambda: self._pin(None))
        self.unpin_button.pack(side="left", padx=(10, 0))
        ttk.Label(prefs, text="      Страны:").pack(side="left")
        self.countries_label = ttk.Label(prefs, text="", font=("Segoe UI", 9, "bold"))
        self.countries_label.pack(side="left", padx=(6, 0))
        ttk.Button(prefs, text="Выбрать…", command=self.on_countries_click).pack(side="left", padx=(10, 0))
        self._show_prefs()

        ttk.Label(
            frame,
            text="Трафик идёт через лучший рабочий прокси, с автопереключением при обрыве. "
                 "Какие программы идут через прокси — «Маршрутизация». Нужны права администратора.",
            foreground="#666", wraplength=640,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 10))

        ttk.Separator(frame).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        # лёгкий режим
        light = ttk.Frame(frame)
        light.grid(row=6, column=0, columnspan=2, sticky="ew")
        ttk.Label(light, text="Только для браузера/приложения: SOCKS5 на 127.0.0.1 :").pack(side="left")
        self.port_var = tk.StringVar(value="1080")
        ttk.Entry(light, textvariable=self.port_var, width=6).pack(side="left", padx=4)
        self.router_button = ttk.Button(light, text="Запустить", command=self.on_router_click)
        self.router_button.pack(side="left", padx=(8, 0))
        self.router_status = ttk.Label(light, text="", foreground="#666")
        self.router_status.pack(side="left", padx=8)

        frame.columnconfigure(0, weight=1)

    def _build_proxy_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Рабочие прокси", padding=12)
        frame.pack(fill="both", expand=True, padx=12, pady=6)

        top = ttk.Frame(frame)
        top.pack(fill="x")
        ttk.Button(top, text="Источники…", command=self.on_sources_click).pack(side="left")
        self.autoheal_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Автоподбор при VPN", variable=self.autoheal_var,
                        command=self.on_autoheal_toggle).pack(side="left", padx=(12, 0))
        ttk.Label(top, text="     таймаут проверки, с").pack(side="left")
        self.timeout_var = tk.StringVar(value="6")
        ttk.Spinbox(top, from_=2, to=30, width=4, textvariable=self.timeout_var).pack(side="left", padx=4)
        self.refresh_button = ttk.Button(top, text="Обновить список", command=self.on_refresh_click)
        self.refresh_button.pack(side="right")

        prog = ttk.Frame(frame)
        prog.pack(fill="x", pady=(8, 4))
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="")
        ttk.Label(prog, textvariable=self.status_var, foreground="#444").pack(anchor="w", pady=(4, 0))

        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True, pady=(4, 0))
        columns = ("type", "address", "country", "latency", "speed", "udp", "rel", "source")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", height=10)
        for col, title, width, anchor in (
            ("type", "Тип", 80, "center"),
            ("address", "Адрес", 220, "w"),
            ("country", "Страна", 140, "w"),
            ("latency", "Отклик, мс", 85, "e"),
            ("speed", "Скорость, КБ/с", 105, "e"),
            ("udp", "Звонки (UDP)", 90, "center"),
            ("rel", "Надёжность", 85, "center"),
            ("source", "Источник", 110, "w"),
        ):
            self.table.heading(col, text=title)
            self.table.column(col, width=width, anchor=anchor)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.bind("<Double-1>", self.on_row_double_click)
        self.table.bind("<Button-3>", self.on_row_menu)  # правый клик — закрепить / скопировать
        self.table.tag_configure("pinned", background="#fff1b8")

        self.counts_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.counts_var, foreground="#666").pack(anchor="w", pady=(6, 0))

    def _build_log_panel(self) -> None:
        frame = ttk.LabelFrame(self.root, text="Журнал", padding=(8, 4))
        frame.pack(fill="both", padx=12, pady=(6, 12))
        self.log_text = ScrolledText(frame, height=8, font=("Consolas", 9), state="disabled", wrap="word")
        self.log_text.pack(fill="both", expand=True)

    # ------------------------------------------------------------ actions

    def on_refresh_click(self) -> None:
        try:
            timeout = float(self.timeout_var.get())
        except ValueError:
            messagebox.showerror(APP_TITLE, "Таймаут должен быть числом")
            return
        if timeout <= 0:
            messagebox.showerror(APP_TITLE, "Таймаут должен быть больше нуля")
            return
        self.ctl.refresh(timeout)

    def on_sources_click(self) -> None:
        path = sources_config.ensure_file()
        try:
            if sys.platform == "win32":
                os.startfile(path)  # откроется в Блокноте / редакторе по умолчанию
            else:
                messagebox.showinfo(APP_TITLE, f"Источники: {path}")
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Не удалось открыть {path}: {exc}")
            return
        self.status_var.set("Отредактируй sources.json, сохрани и нажми «Обновить список»")

    def on_routing_click(self) -> None:
        RoutingDialog(self.root, self.ctl.routing, self._on_routing_done)

    def _on_routing_done(self, routing: app_routing.RoutingSettings) -> None:
        self.ctl.set_routing(routing)
        self._show_routing()

    def _show_routing(self) -> None:
        r = self.ctl.routing
        mode = app_routing.MODES[r.mode]
        if r.mode == app_routing.MODE_ALL:
            self.routing_label.configure(text=mode)
            return
        titles = ", ".join(a.title for a in r.apps) or "приложения не выбраны"
        if len(titles) > 70:
            titles = titles[:67] + "…"
        self.routing_label.configure(text=f"{mode} — {titles}")

    # ---- закреплённый прокси и страны

    def _show_prefs(self) -> None:
        s = self.ctl.settings
        pin = s.pinned_address
        if pin:
            r = next((r for r in self.ctl.results if r.proxy.address == pin), None)
            where = f" ({r.proxy.country})" if r and r.proxy.country else ""
            state = "" if r else " — сейчас не работает, автовыбор"
            self.pin_label.configure(text=f"★ закреплён {pin}{where}{state}")
            self.unpin_button.pack(side="left", padx=(10, 0), after=self.pin_label)
        else:
            self.pin_label.configure(text="автовыбор лучшего (закрепить — правый клик по строке в таблице)")
            self.unpin_button.pack_forget()
        self.countries_label.configure(text=", ".join(s.countries) if s.countries else "любые")

    def _pin(self, address: str | None) -> None:
        self.ctl.pin_proxy(address)
        self._show_prefs()
        self._render_results(self.ctl.results)

    def on_countries_click(self) -> None:
        CountriesDialog(self.root, self.ctl.results, self.ctl.settings.countries, self._on_countries_done)

    def _on_countries_done(self, countries: list[str]) -> None:
        s = app_settings.from_dict(dataclasses.asdict(self.ctl.settings))
        s.countries = countries
        self.ctl.update_settings(s)
        self._show_prefs()

    def on_settings_click(self) -> None:
        SettingsDialog(self.root, self.ctl.settings, self.tray.available, self._on_settings_done,
                       self._relaunch_as_admin)

    def _relaunch_as_admin(self) -> None:
        if singbox_manager.relaunch_as_admin():
            self.quit()
        else:
            messagebox.showerror(APP_TITLE, "Не удалось перезапустить с правами администратора")

    def _on_settings_done(self, settings: app_settings.AppSettings) -> None:
        self.ctl.update_settings(settings)

    def on_row_menu(self, event: tk.Event) -> None:
        iid = self.table.identify_row(event.y)
        if not iid:
            return
        self.table.selection_set(iid)
        menu = tk.Menu(self.root, tearoff=False)
        if iid == self.ctl.settings.pinned_address:
            menu.add_command(label="Открепить", command=lambda: self._pin(None))
        else:
            menu.add_command(label="★ Закрепить для VPN", command=lambda: self._pin(iid))
        menu.add_command(label="Скопировать адрес", command=lambda: self.on_row_double_click(None))
        menu.tk_popup(event.x_root, event.y_root)

    def on_autoheal_toggle(self) -> None:
        self.ctl.autoheal = bool(self.autoheal_var.get())

    def on_vpn_click(self) -> None:
        state = self.ctl.vpn_state
        if state == "on":
            self.ctl.disconnect_vpn()
            return
        if state == "connecting":
            return
        if not singbox_manager.is_admin():
            if messagebox.askyesno(
                APP_TITLE,
                "Для VPN нужны права администратора (Windows требует их для создания "
                "виртуального сетевого адаптера).\n\nПерезапустить программу от имени администратора?",
            ):
                if singbox_manager.relaunch_as_admin():
                    self.quit()  # не on_close: тот свернул бы в трей, и остались бы две копии
                else:
                    messagebox.showerror(APP_TITLE, "Не удалось перезапустить с правами администратора")
            return
        if not self.ctl.results:
            messagebox.showinfo(APP_TITLE, "Сначала нажми «Обновить список» — рабочих прокси пока нет.")
            return
        self.ctl.connect_vpn()

    def on_router_click(self) -> None:
        if self.ctl.router_running:
            self.ctl.stop_router()
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror(APP_TITLE, "Порт должен быть числом")
            return
        self.ctl.start_router(port)

    def on_row_double_click(self, _event: tk.Event | None) -> None:
        sel = self.table.selection()
        if not sel:
            return
        ptype, address, *_ = self.table.item(sel[0], "values")
        scheme = {"SOCKS5": "socks5", "SOCKS4": "socks4", "HTTPS": "http"}.get(ptype, "socks5")
        text = f"{scheme}://{address}"
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set(f"Скопировано: {text}")

    def on_close(self) -> None:
        """Крестик окна: свернуть в трей (если так настроено и трей есть) или выйти."""
        if self.ctl.settings.close_to_tray and self.tray.available:
            self.hide_window()
            if not self._tray_hint_shown:
                self._tray_hint_shown = True
                self.tray.notify("Программа продолжает работать в трее. Выход — через меню значка.")
            return
        self.quit()

    # ------------------------------------------------------------ events

    def _poll_events(self) -> None:
        try:
            while True:
                event = self.ctl.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        try:
            while not self._closed:
                self._handle_tray_action(self.tray.actions.get_nowait())
        except queue.Empty:
            pass
        if not self._closed:  # после «Выход» из меню трея окна уже нет
            self.root.after(100, self._poll_events)

    def _handle_event(self, event: tuple) -> None:
        kind = event[0]
        if kind == "log":
            self._append_log(event[1])
        elif kind == "status":
            self.status_var.set(event[1])
        elif kind == "progress":
            done, total = event[1], event[2]
            if total == 0:
                self.progress.configure(mode="indeterminate")
                self.progress.start(12)
            else:
                self.progress.stop()
                # текст статуса (с названием этапа) приходит отдельным событием
                self.progress.configure(mode="determinate", maximum=total, value=done)
        elif kind == "results":
            self._render_results(event[1])
            self._show_prefs()  # закреплённый мог перестать работать или ожить
        elif kind == "busy":
            busy = event[1]
            self.refresh_button.configure(state="disabled" if busy else "normal")
            self.tray.set_busy(busy)
            if not busy:
                self.progress.stop()
                self.progress.configure(mode="determinate")
        elif kind == "router":
            running = event[1]
            self.router_button.configure(text="Остановить" if running else "Запустить")
            self.router_status.configure(
                text="работает — пропиши SOCKS5 127.0.0.1:%s в браузере" % self.port_var.get() if running else ""
            )
        elif kind == "vpn":
            self._apply_vpn_state(event[1])
        elif kind == "vpn_info":
            text, level = event[1], event[2]
            color = {"ok": "#2e7d32", "wait": "#8a6d00", "warn": "#c62828"}.get(level, "#444")
            self.vpn_info.configure(text=text, foreground=color)
            self.tray.set_tooltip(f"{APP_TITLE} — {VPN_LABELS[self.ctl.vpn_state][0].strip('● ')}\n{text}")
        elif kind == "ask":
            text, holder = event[1], event[2]
            self.show_window()  # вопрос из трея должен быть виден
            try:
                holder["answer"] = messagebox.askyesnocancel(APP_TITLE, text)
            finally:
                holder["event"].set()
        elif kind == "error":
            self._append_log("ОШИБКА: " + event[1])
            if self._hidden and self.tray.available:
                self.tray.notify(event[1], f"{APP_TITLE}: ошибка")  # окно в трее — не всплываем
            else:
                messagebox.showerror(APP_TITLE, event[1])

    def _apply_vpn_state(self, state: str) -> None:
        text, color, button_text = VPN_LABELS[state]
        self.vpn_status.configure(text=text, foreground=color)
        self.vpn_button.configure(text=button_text, state="disabled" if state == "connecting" else "normal")
        self.tray.set_state(state, f"{APP_TITLE} — {text.strip('● ')}")

    def _render_results(self, results: list[CheckResult]) -> None:
        self.table.delete(*self.table.get_children())
        counts = {"SOCKS5": 0, "SOCKS4": 0, "HTTPS": 0}
        pinned = self.ctl.settings.pinned_address
        for r in results:
            p = r.proxy
            if self.table.exists(p.address):
                continue
            counts[p.type.value] = counts.get(p.type.value, 0) + 1
            latency = f"{r.latency_ms:.0f}" if r.latency_ms is not None else "—"
            speed = f"{r.speed_kbps:.0f}" if r.speed_kbps is not None else "—"
            udp = "да" if r.udp else "—"
            rel = f"{r.rep_ok}/{r.rep_checks}" if r.rep_checks > 1 else "новый"
            self.table.insert("", "end", iid=p.address, tags=("pinned",) if p.address == pinned else (),
                              values=(p.type.value, p.address, p.country or "—", latency, speed, udp, rel,
                                      p.source or "—"))
        total = sum(counts.values())
        self.counts_var.set(
            f"Всего рабочих: {total}   ·   SOCKS5: {counts['SOCKS5']}   ·   SOCKS4: {counts['SOCKS4']}   ·   "
            f"HTTPS: {counts['HTTPS']}   ·   с UDP: {sum(1 for r in results if r.udp)}   "
            "(двойной клик — скопировать адрес, правый клик — закрепить для VPN)"
        )

    def _append_log(self, line: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        # не даём журналу разрастись бесконечно
        if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


class RoutingDialog:
    """Окно «Маршрутизация»: режим + какие приложения через прокси.

    Слева — выбранные приложения, справа — запущенные программы (двойной
    клик или «← Добавить»), снизу — популярные программы и выбор любого .exe.
    """

    HINTS = {
        app_routing.MODE_ALL: "Через прокси идёт весь трафик компьютера. Список приложений не используется.",
        app_routing.MODE_ONLY: "Через прокси пойдут ТОЛЬКО эти приложения, всё остальное — напрямую, "
                               "как без VPN. Если бесплатные прокси отвалятся, остальной интернет продолжит работать.",
        app_routing.MODE_EXCEPT: "Эти приложения пойдут НАПРЯМУЮ, мимо прокси, а всё остальное — через прокси. "
                                 "Удобно для игр, банков и всего, что работает и без VPN.",
    }

    def __init__(self, parent: tk.Tk, routing: app_routing.RoutingSettings, on_done) -> None:
        self.on_done = on_done
        self.apps = [app_routing.AppEntry(a.title, list(a.processes)) for a in routing.apps]
        self.running: list[app_routing.RunningApp] = []

        top = self.top = tk.Toplevel(parent)
        top.title("Маршрутизация по приложениям")
        top.geometry("860x520")
        top.minsize(700, 420)
        top.transient(parent)
        top.grab_set()

        # режим
        modes = ttk.Frame(top, padding=(12, 12, 12, 0))
        modes.pack(fill="x")
        self.mode_var = tk.StringVar(value=routing.mode)
        for mode, label in app_routing.MODES.items():
            ttk.Radiobutton(modes, text=label, value=mode, variable=self.mode_var,
                            command=self._on_mode).pack(side="left", padx=(0, 16))
        self.hint = ttk.Label(top, text="", foreground="#555", wraplength=820, padding=(12, 6, 12, 0))
        self.hint.pack(fill="x")

        body = ttk.Frame(top, padding=12)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)

        # выбранные
        self.sel_frame = ttk.LabelFrame(body, text="Выбранные приложения", padding=6)
        self.sel_frame.grid(row=0, column=0, sticky="nsew")
        self.sel_tree = self._tree(self.sel_frame, ("Приложение", 170), ("Процессы", 170))
        self.sel_tree.bind("<Double-1>", lambda _e: self._remove())
        self.sel_tree.bind("<Delete>", lambda _e: self._remove())

        mid = ttk.Frame(body, padding=8)
        mid.grid(row=0, column=1)
        ttk.Button(mid, text="← Добавить", command=self._add_selected_running).pack(fill="x", pady=4)
        ttk.Button(mid, text="Убрать →", command=self._remove).pack(fill="x", pady=4)

        # запущенные
        run_frame = ttk.LabelFrame(body, text="Запущенные программы", padding=6)
        run_frame.grid(row=0, column=2, sticky="nsew")
        search = ttk.Frame(run_frame)
        search.pack(fill="x", pady=(0, 6))
        ttk.Label(search, text="Поиск:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render_running())
        ttk.Entry(search, textvariable=self.search_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(search, text="Обновить", command=self._load_running).pack(side="left")
        self.run_tree = self._tree(run_frame, ("Программа", 190), ("Файл", 150))
        self.run_tree.bind("<Double-1>", lambda _e: self._add_selected_running())

        # низ
        bottom = ttk.Frame(top, padding=(12, 0, 12, 12))
        bottom.pack(fill="x")
        popular = ttk.Menubutton(bottom, text="Популярные ▾")
        menu = tk.Menu(popular, tearoff=False)
        for known in app_routing.KNOWN_APPS:
            menu.add_command(label=known.title, command=lambda k=known: self._add(
                app_routing.AppEntry(k.title, list(k.processes))))
        popular["menu"] = menu
        popular.pack(side="left")
        ttk.Button(bottom, text="Выбрать .exe…", command=self._browse).pack(side="left", padx=8)
        ttk.Button(bottom, text="Отмена", command=top.destroy).pack(side="right")
        ttk.Button(bottom, text="Готово", command=self._done).pack(side="right", padx=8)

        self._on_mode()
        self._render_selected()
        self._load_running()

    @staticmethod
    def _tree(parent, *columns) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=12)
        for name, width in columns:
            tree.heading(name, text=name)
            tree.column(name, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return tree

    # ---- режим

    def _on_mode(self) -> None:
        mode = self.mode_var.get()
        self.hint.configure(text=self.HINTS[mode])
        self.sel_frame.configure(text={
            app_routing.MODE_ONLY: "Через прокси идут только они",
            app_routing.MODE_EXCEPT: "Идут напрямую, мимо прокси",
        }.get(mode, "Выбранные приложения (сейчас не используются)"))

    # ---- выбранные

    def _render_selected(self) -> None:
        self.sel_tree.delete(*self.sel_tree.get_children())
        for i, app in enumerate(self.apps):
            self.sel_tree.insert("", "end", iid=str(i), values=(app.title, ", ".join(app.processes)))
        self._render_running()

    def _add(self, app: app_routing.AppEntry) -> None:
        if any(a.key() & app.key() for a in self.apps):
            return  # уже есть (или его процесс уже в другом выбранном)
        self.apps.append(app)
        self._render_selected()

    def _remove(self) -> None:
        drop = {int(i) for i in self.sel_tree.selection()}
        if drop:
            self.apps = [a for i, a in enumerate(self.apps) if i not in drop]
            self._render_selected()

    def _browse(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            parent=self.top, title="Выберите программу",
            filetypes=[("Программы", "*.exe"), ("Все файлы", "*.*")],
            initialdir=os.environ.get("ProgramFiles", "C:\\"),
        )
        if path:
            exe = pathlib.Path(path).name
            self._add(app_routing.app_for_exe(exe, pathlib.Path(path).stem))

    # ---- запущенные

    def _load_running(self) -> None:
        self.running = []
        self.run_tree.delete(*self.run_tree.get_children())
        self.run_tree.insert("", "end", values=("Загружаю список программ…", ""))
        # список собирается ~1 с в фоне; tkinter нельзя трогать из чужого
        # потока — результат приходит через очередь, окно забирает его само
        result: "queue.Queue[list]" = queue.Queue()
        threading.Thread(target=lambda: result.put(app_routing.list_running_apps()), daemon=True).start()
        self._wait_running(result)

    def _wait_running(self, result: "queue.Queue[list]") -> None:
        try:
            apps = result.get_nowait()
        except queue.Empty:
            if self.top.winfo_exists():
                self.top.after(100, self._wait_running, result)
            return
        self.running = apps
        self.run_tree.delete(*self.run_tree.get_children())
        if not apps:
            self.run_tree.insert("", "end", values=("Не удалось получить список — добавьте через «Выбрать .exe…»", ""))
        self._render_running()

    def _render_running(self) -> None:
        if not self.running:
            return
        chosen = set().union(*(a.key() for a in self.apps)) if self.apps else set()
        query = self.search_var.get().strip().lower()
        self.run_tree.delete(*self.run_tree.get_children())
        for i, app in enumerate(self.running):
            if app.exe.lower() in chosen:
                continue
            if query and query not in app.title.lower() and query not in app.exe.lower():
                continue
            title = ("● " if app.windowed else "   ") + app.title  # ● — у программы есть окно
            self.run_tree.insert("", "end", iid=str(i), values=(title, app.exe))

    def _add_selected_running(self) -> None:
        for iid in self.run_tree.selection():
            if iid.isdigit():
                app = self.running[int(iid)]
                self._add(app_routing.app_for_exe(app.exe, app.title))

    # ---- готово

    def _done(self) -> None:
        mode = self.mode_var.get()
        if mode == app_routing.MODE_ONLY and not self.apps:
            if not messagebox.askyesno(
                APP_TITLE, "Не выбрано ни одного приложения — через прокси не пойдёт ничего.\n\nСохранить так?",
                parent=self.top,
            ):
                return
        self.top.destroy()
        self.on_done(app_routing.RoutingSettings(mode, self.apps))


class SettingsDialog:
    """Окно «Настройки»: автозапуск, автоподключение, трей, фоновое обновление."""

    REFRESH = {0: "выключено", 1: "каждый час", 2: "каждые 2 ч", 3: "каждые 3 ч", 6: "каждые 6 ч", 12: "каждые 12 ч"}

    def __init__(self, parent: tk.Tk, settings: app_settings.AppSettings, tray_available: bool,
                 on_done, relaunch_as_admin) -> None:
        self.base, self.on_done, self.relaunch_as_admin = settings, on_done, relaunch_as_admin
        top = self.top = tk.Toplevel(parent)
        top.title("Настройки")
        top.resizable(False, False)
        top.transient(parent)
        top.grab_set()
        frm = ttk.Frame(top, padding=16)
        frm.pack(fill="both", expand=True)

        def hint(text: str) -> None:
            ttk.Label(frm, text=text, foreground="#666", wraplength=520).pack(anchor="w", padx=(22, 0), pady=(0, 8))

        self.autostart_was = autostart.is_enabled()
        self.autostart_var = tk.BooleanVar(value=self.autostart_was)
        ttk.Checkbutton(frm, text="Запускать вместе с Windows", variable=self.autostart_var,
                        command=self._on_autostart).pack(anchor="w")
        hint("Сразу в трей и сразу с правами администратора — без окна «Разрешить изменения?».")

        self.connect_var = tk.BooleanVar(value=settings.auto_connect)
        ttk.Checkbutton(frm, text="Подключать VPN сразу после запуска", variable=self.connect_var).pack(anchor="w")
        hint("Если список прокси пуст — сначала обновит его.")

        self.tray_var = tk.BooleanVar(value=settings.close_to_tray)
        tray_check = ttk.Checkbutton(frm, text="Крестик окна сворачивает в трей", variable=self.tray_var)
        tray_check.pack(anchor="w")
        if tray_available:
            hint("Программа и VPN продолжают работать; выход — через меню значка в трее.")
        else:
            tray_check.state(["disabled"])
            hint("Трей недоступен: не установлены pystray и Pillow — запусти программу через ProxyParser.bat, "
                 "он их доустановит.")

        row = ttk.Frame(frm)
        row.pack(anchor="w", pady=(4, 0))
        ttk.Label(row, text="Обновлять список прокси в фоне:").pack(side="left")
        self.refresh_var = tk.StringVar(value=self.REFRESH.get(settings.auto_refresh_hours, "каждые 3 ч"))
        ttk.Combobox(row, textvariable=self.refresh_var, values=list(self.REFRESH.values()), state="readonly",
                     width=14).pack(side="left", padx=(8, 0))
        hint("Работающий VPN при этом не перезапускается, пока его прокси отвечают, — звонки и загрузки "
             "не рвутся. Свежие прокси пойдут в дело при автоподборе и следующем подключении.")

        buttons = ttk.Frame(frm)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Отмена", command=top.destroy).pack(side="right")
        ttk.Button(buttons, text="Готово", command=self._done).pack(side="right", padx=8)

    def _on_autostart(self) -> None:
        if self.autostart_var.get() and not self.connect_var.get():
            self.connect_var.set(True)  # включают автозапуск — почти всегда ради VPN

    def _settings(self) -> app_settings.AppSettings:
        s = app_settings.from_dict(dataclasses.asdict(self.base))
        s.auto_connect = bool(self.connect_var.get())
        s.close_to_tray = bool(self.tray_var.get())
        s.auto_refresh_hours = next(h for h, label in self.REFRESH.items() if label == self.refresh_var.get())
        return s

    def _done(self) -> None:
        want = bool(self.autostart_var.get())
        if want != self.autostart_was:
            if not singbox_manager.is_admin():
                if messagebox.askyesno(
                    APP_TITLE,
                    "Включать и выключать автозапуск с правами администратора Windows разрешает только "
                    "администратору.\n\nПерезапустить программу от имени администратора? Остальные настройки "
                    "сохранятся, автозапуск включи ещё раз после перезапуска.", parent=self.top,
                ):
                    self.top.destroy()
                    self.on_done(self._settings())
                    self.relaunch_as_admin()
                return
            self.top.configure(cursor="watch")
            self.top.update()
            ok, err = autostart.enable() if want else autostart.disable()
            self.top.configure(cursor="")
            if not ok:
                messagebox.showerror(APP_TITLE, f"Не удалось {'включить' if want else 'выключить'} автозапуск: {err}",
                                     parent=self.top)
                return
        self.top.destroy()
        self.on_done(self._settings())


class CountriesDialog:
    """Окно «Страны»: из каких стран брать прокси (для VPN и лёгкого режима)."""

    def __init__(self, parent: tk.Tk, results: list[CheckResult], selected: list[str], on_done) -> None:
        self.on_done = on_done
        stats: dict[str, list] = {}
        for r in results:
            code = (r.proxy.country_code or "").upper()
            if r.working and code:
                entry = stats.setdefault(code, [r.proxy.country or code, 0])
                entry[1] += 1
        for code in selected:  # выбранные раньше, но без рабочих прокси сейчас — тоже показать
            stats.setdefault(code, [code, 0])
        self.codes = sorted(stats, key=lambda c: (-stats[c][1], stats[c][0]))

        top = self.top = tk.Toplevel(parent)
        top.title("Страны прокси")
        top.geometry("420x460")
        top.transient(parent)
        top.grab_set()
        frm = ttk.Frame(top, padding=12)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, wraplength=390, foreground="#555",
                  text="Отметь страны — в VPN и лёгкий режим пойдут прокси только из них. Ничего не отмечено — "
                       "любые. Закреплённый прокси работает в любом случае. Если в выбранных странах рабочих "
                       "не окажется, программа возьмёт любые и предупредит в журнале.").pack(anchor="w")

        box = ttk.Frame(frm)
        box.pack(fill="both", expand=True, pady=8)
        self.listbox = tk.Listbox(box, selectmode="multiple", activestyle="none", exportselection=False,
                                  font=("Segoe UI", 10))
        scroll = ttk.Scrollbar(box, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        for i, code in enumerate(self.codes):
            name, count = stats[code]
            self.listbox.insert("end", f"{name} ({code}) — {count or 'нет рабочих сейчас'}")
            if code in selected:
                self.listbox.selection_set(i)

        buttons = ttk.Frame(frm)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Любые", command=lambda: self.listbox.selection_clear(0, "end")).pack(side="left")
        ttk.Button(buttons, text="Только Европа", command=self._europe).pack(side="left", padx=8)
        ttk.Button(buttons, text="Отмена", command=top.destroy).pack(side="right")
        ttk.Button(buttons, text="Готово", command=self._done).pack(side="right", padx=8)

    def _europe(self) -> None:
        self.listbox.selection_clear(0, "end")
        for i, code in enumerate(self.codes):
            if code in app_settings.EUROPE:
                self.listbox.selection_set(i)

    def _done(self) -> None:
        chosen = sorted(self.codes[i] for i in self.listbox.curselection())
        self.top.destroy()
        self.on_done(chosen)


def selfcheck(report_path: str) -> None:
    """Проверка сборки без окон: всё ли нужное внутри exe работает. Пишет
    отчёт в JSON и выходит (используется при сборке и в тестах)."""
    import json

    from proxyparser import paths

    report: dict = {"version": __version__, "frozen": paths.FROZEN, "app_dir": str(paths.APP_DIR)}
    try:
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        report["tkinter"] = True
    except Exception as exc:  # noqa: BLE001
        report["tkinter"] = repr(exc)
    report["tray"] = tray.AVAILABLE
    try:
        import importlib

        importlib.import_module("pystray._win32")  # бэкенд трея для Windows — должен попасть в exe
        report["tray_backend"] = True
    except Exception as exc:  # noqa: BLE001
        report["tray_backend"] = repr(exc)
    import requests
    import ssl

    report["requests"] = requests.__version__
    # сертификаты внутри exe: и у requests (загрузка списков), и у ssl (проверка прокси)
    report["ssl_ca_certs"] = ssl.create_default_context().cert_store_stats().get("x509_ca", 0)
    try:
        report["https"] = requests.get("https://api.github.com/zen", timeout=15).status_code
    except Exception as exc:  # noqa: BLE001
        report["https"] = repr(exc)[:200]
    report["launch_command"] = list(paths.launch_command())
    report["own_process_paths"] = singbox_manager.own_process_paths()
    report["results_dir"] = str(__import__("proxyparser.storage", fromlist=["x"]).RESULTS_DIR)
    report["settings_file"] = str(app_settings.SETTINGS_FILE)
    pathlib.Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")


def main() -> None:
    args = sys.argv[1:]
    if args[:1] == ["--selfcheck"] and len(args) > 1:
        selfcheck(args[1])
        return
    # одна копия программы: если уже запущена (в трее) — показать её окно и выйти;
    # после перезапуска от администратора — подождать, пока закроется прежняя
    lock = single_instance.acquire(wait_s=10 if singbox_manager.RELAUNCHED_ARG in args else 0)
    if lock is None:
        if not single_instance.notify_existing():
            messagebox.showinfo(APP_TITLE, "Программа уже запущена — она в трее, рядом с часами.")
        return
    root = tk.Tk()
    app = App(root, start_hidden=autostart.AUTOSTART_ARG in args)
    single_instance.serve(lock, lambda: app.tray.actions.put("show"))
    root.mainloop()
    lock.close()


if __name__ == "__main__":
    main()

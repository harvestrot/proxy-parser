"""Тёмная тема окна: палитра, стили ttk, тёмный заголовок Windows и
скруглённые кнопки/индикаторы (рисуются Pillow со сглаживанием).

Без внешних тем: всё на встроенном движке ttk «clam», которому можно задать
любые цвета. Если Pillow нет, кнопки и индикатор откатываются на простые.
"""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk

try:  # pragma: no cover — зависит от установленных пакетов
    from PIL import Image, ImageDraw, ImageFilter, ImageTk
    HAS_PIL = True
except Exception:  # noqa: BLE001
    HAS_PIL = False

# ------------------------------------------------------------------ палитра
BG = "#0b0d12"          # фон окна
SURFACE = "#141821"     # карточки
RAISED = "#1d222d"      # кнопки, заголовки таблиц
HOVER = "#272d3a"
FIELD = "#0f1219"       # поля ввода
BORDER = "#252b37"
TEXT = "#e8eaf0"
MUTED = "#8b93a7"
FAINT = "#5c6578"
ACCENT = "#8b5cf6"      # фиолетовый
ACCENT_HOVER = "#9f7aff"
ACCENT_PRESS = "#7646e6"
ACCENT_DIM = "#2b2350"  # выделение строк
GREEN = "#34d399"
AMBER = "#fbbf24"
RED = "#f87171"
PIN_BG, PIN_FG = "#2e2814", "#fcd34d"

FONT = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI Semibold", 10)
FONT_CAPTION = ("Segoe UI Semibold", 8)
FONT_TITLE = ("Segoe UI Semibold", 17)
FONT_STATUS = ("Segoe UI Semibold", 19)
FONT_MONO = ("Cascadia Mono", 9)


def apply(root: tk.Tk) -> None:
    """Настроить стили ttk и цвета обычных tk-виджетов для всего приложения."""
    root.configure(bg=BG)
    s = ttk.Style(root)
    s.theme_use("clam")

    flat = {"lightcolor": SURFACE, "darkcolor": SURFACE, "bordercolor": SURFACE}
    s.configure(".", background=SURFACE, foreground=TEXT, fieldbackground=FIELD, troughcolor=FIELD,
                selectbackground=ACCENT_DIM, selectforeground=TEXT, insertcolor=TEXT, focuscolor=SURFACE,
                font=FONT, **flat)
    s.map(".", foreground=[("disabled", FAINT)])

    # подписи
    s.configure("TLabel", background=SURFACE, foreground=TEXT)
    s.configure("Muted.TLabel", foreground=MUTED)
    s.configure("Faint.TLabel", foreground=FAINT, font=FONT_SMALL)
    s.configure("Bold.TLabel", font=FONT_BOLD)
    s.configure("Caption.TLabel", foreground=FAINT, font=FONT_CAPTION)
    s.configure("CardTitle.TLabel", font=("Segoe UI Semibold", 12))
    s.configure("Status.TLabel", font=FONT_STATUS)
    for name, color in (("Ok", GREEN), ("Wait", AMBER), ("Warn", RED)):
        s.configure(f"{name}.TLabel", foreground=color)
    # то, что лежит прямо на фоне окна (шапка)
    s.configure("Bg.TFrame", background=BG)
    s.configure("Bg.TLabel", background=BG, foreground=TEXT)
    s.configure("BgTitle.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
    s.configure("BgMuted.TLabel", background=BG, foreground=FAINT, font=FONT_SMALL)
    s.configure("Badge.TLabel", background=ACCENT_DIM, foreground="#c4b5fd", font=FONT_CAPTION, padding=(8, 2))
    # плитки на главном экране
    s.configure("Tile.TFrame", background=FIELD)
    s.configure("TileCaption.TLabel", background=FIELD, foreground=FAINT, font=FONT_CAPTION)
    s.configure("TileValue.TLabel", background=FIELD, foreground=TEXT, font=("Segoe UI Semibold", 11))
    s.configure("TilePin.TLabel", background=FIELD, foreground=PIN_FG, font=("Segoe UI Semibold", 11))
    s.configure("TileSub.TLabel", background=FIELD, foreground=MUTED, font=FONT_SMALL)

    # кнопки
    def button(name: str, bg: str, fg: str, hover: str, press: str, border: str | None = None, **kw) -> None:
        s.configure(name, background=bg, foreground=fg, bordercolor=border or bg, lightcolor=bg, darkcolor=bg,
                    focuscolor=bg, relief="flat", padding=kw.pop("padding", (14, 6)), **kw)
        s.map(name, background=[("disabled", RAISED), ("pressed", press), ("active", hover)],
              lightcolor=[("pressed", press), ("active", hover)], darkcolor=[("pressed", press), ("active", hover)],
              bordercolor=[("active", hover)], foreground=[("disabled", FAINT)])

    button("TButton", RAISED, TEXT, HOVER, BORDER, border=BORDER)
    button("Accent.TButton", ACCENT, "#ffffff", ACCENT_HOVER, ACCENT_PRESS, font=FONT_BOLD)
    button("Danger.TButton", "#3a1d24", "#fca5a5", "#4a232c", "#2c161b")
    button("Link.TButton", SURFACE, "#b69cff", SURFACE, SURFACE, padding=(4, 0))
    s.map("Link.TButton", foreground=[("disabled", FAINT), ("active", "#d4c5ff")],
          background=[("disabled", SURFACE), ("active", SURFACE)])
    button("BgLink.TButton", BG, MUTED, BG, BG, padding=(8, 4))
    s.map("BgLink.TButton", foreground=[("active", TEXT)])
    button("TileLink.TButton", FIELD, "#b69cff", FIELD, FIELD, padding=(0, 0), font=FONT_SMALL)
    s.map("TileLink.TButton", foreground=[("disabled", FAINT), ("active", "#d4c5ff")],
          background=[("disabled", FIELD), ("active", FIELD)])
    s.configure("TMenubutton", background=RAISED, foreground=TEXT, arrowcolor=MUTED, bordercolor=BORDER,
                lightcolor=RAISED, darkcolor=RAISED, relief="flat", padding=(12, 6))
    s.map("TMenubutton", background=[("active", HOVER)])

    # поля ввода
    for name in ("TEntry", "TSpinbox", "TCombobox"):
        s.configure(name, fieldbackground=FIELD, foreground=TEXT, bordercolor=BORDER, lightcolor=FIELD,
                    darkcolor=FIELD, background=RAISED, arrowcolor=MUTED, insertcolor=TEXT, padding=(6, 4))
        s.map(name, bordercolor=[("focus", ACCENT)], lightcolor=[("focus", FIELD)],
              fieldbackground=[("readonly", FIELD), ("disabled", SURFACE)],
              foreground=[("disabled", FAINT), ("readonly", TEXT)], arrowcolor=[("active", TEXT)],
              background=[("active", HOVER)])
    root.option_add("*TCombobox*Listbox.background", RAISED)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_DIM)
    root.option_add("*TCombobox*Listbox.selectForeground", TEXT)
    root.option_add("*TCombobox*Listbox.borderWidth", 0)

    # галочки и переключатели: свои картинки (встроенная галочка clam — крестик)
    if HAS_PIL:
        _custom_indicators(root, s)
    for name in ("TCheckbutton", "TRadiobutton"):
        s.configure(name, background=SURFACE, foreground=TEXT, indicatorbackground=FIELD,
                    indicatorforeground="#ffffff", indicatormargin=(0, 0, 8, 0), focuscolor=SURFACE,
                    upperbordercolor=BORDER, lowerbordercolor=BORDER)
        s.map(name, indicatorbackground=[("selected", ACCENT), ("active", HOVER)],
              background=[("active", SURFACE)], foreground=[("disabled", FAINT)])

    # таблица
    s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT, rowheight=28,
                borderwidth=0, relief="flat", **flat)
    s.map("Treeview", background=[("selected", ACCENT_DIM)], foreground=[("selected", "#ffffff")])
    s.configure("Treeview.Heading", background=RAISED, foreground=MUTED, font=FONT_CAPTION, relief="flat",
                padding=(8, 7), bordercolor=RAISED, lightcolor=RAISED, darkcolor=RAISED)
    s.map("Treeview.Heading", background=[("active", HOVER)], foreground=[("active", TEXT)])
    s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])  # без рамки вокруг

    # полосы прокрутки и прогресс
    for orient in ("Vertical", "Horizontal"):
        s.configure(f"{orient}.TScrollbar", background=RAISED, troughcolor=SURFACE, bordercolor=SURFACE,
                    lightcolor=RAISED, darkcolor=RAISED, arrowcolor=MUTED, gripcount=0, arrowsize=12)
        s.map(f"{orient}.TScrollbar", background=[("active", HOVER), ("pressed", BORDER)])
    s.configure("Horizontal.TProgressbar", troughcolor=FIELD, background=ACCENT, bordercolor=FIELD,
                lightcolor=ACCENT, darkcolor=ACCENT, thickness=5)

    # рамки и разделители (в диалогах)
    s.configure("TFrame", background=SURFACE)
    s.configure("TLabelframe", background=SURFACE, bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE)
    s.configure("TLabelframe.Label", background=SURFACE, foreground=MUTED, font=FONT_CAPTION)
    s.configure("TSeparator", background=BORDER)

    # обычные tk-виджеты: меню, списки, текст
    for pattern, value in (
        ("*Menu.background", RAISED), ("*Menu.foreground", TEXT), ("*Menu.activeBackground", ACCENT_DIM),
        ("*Menu.activeForeground", "#ffffff"), ("*Menu.borderWidth", 0), ("*Menu.activeBorderWidth", 0),
        ("*Menu.relief", "flat"), ("*Menu.font", FONT),
        ("*Listbox.background", FIELD), ("*Listbox.foreground", TEXT), ("*Listbox.selectBackground", ACCENT_DIM),
        ("*Listbox.selectForeground", "#ffffff"), ("*Listbox.borderWidth", 0), ("*Listbox.highlightThickness", 0),
        ("*Listbox.font", FONT),
    ):
        root.option_add(pattern, value)


def _indicator(kind: str, on: bool, hover: bool, size: int = 18, gap: int = 8) -> "ImageTk.PhotoImage":
    """Галочка (скруглённый квадрат) или переключатель (круг) со сглаживанием;
    справа — прозрачный отступ до подписи."""
    k = 4
    img = Image.new("RGBA", ((size + gap) * k, size * k), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    box = (k, k, size * k - k, size * k - k)
    fill = ACCENT if on else (HOVER if hover else FIELD)
    outline = ACCENT if on else ("#3a4252" if hover else "#323949")
    if kind == "check":
        d.rounded_rectangle(box, 4 * k, fill=fill, outline=outline, width=k + k // 2)
        if on:
            d.line([(4.5 * k, 9.5 * k), (7.5 * k, 12.5 * k), (13.5 * k, 5.5 * k)], fill="white", width=2 * k,
                   joint="curve")
    else:
        d.ellipse(box, fill=FIELD if on else fill, outline=outline, width=k + k // 2)
        if on:
            c = size * k / 2
            d.ellipse((c - 4.5 * k, c - 4.5 * k, c + 4.5 * k, c + 4.5 * k), fill=ACCENT)
    return ImageTk.PhotoImage(img.resize((size + gap, size), Image.LANCZOS))


def _custom_indicators(root: tk.Tk, s: ttk.Style) -> None:
    images = root._theme_images = {}  # держим ссылки, иначе картинки исчезнут
    for kind, widget in (("check", "Checkbutton"), ("radio", "Radiobutton")):
        for on in (False, True):
            for hover in (False, True):
                images[(kind, on, hover)] = _indicator(kind, on, hover)
        element = f"Dark.{widget}.indicator"
        s.element_create(element, "image", images[(kind, False, False)],
                         ("selected", "active", images[(kind, True, True)]),
                         ("selected", images[(kind, True, False)]),
                         ("active", images[(kind, False, True)]))
        s.layout(f"T{widget}", [(f"{widget}.padding", {"sticky": "nswe", "children": [
            (element, {"side": "left", "sticky": ""}),
            (f"{widget}.label", {"side": "left", "sticky": "nswe"}),
        ]})])


def _rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def dark_titlebar(win: tk.Misc, caption: str = BG) -> None:
    """Тёмная строка заголовка Windows в цвет окна (Windows 10 20H1+ / 11)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        dwm = ctypes.windll.dwmapi
        on = ctypes.c_int(1)
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(on), 4)   # DWMWA_USE_IMMERSIVE_DARK_MODE
        r, g, b = _rgb(caption)
        color = ctypes.c_int(r | (g << 8) | (b << 16))               # COLORREF = 0x00BBGGRR
        dwm.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(color), 4)  # DWMWA_CAPTION_COLOR (Windows 11)
        r, g, b = _rgb(TEXT)
        text = ctypes.c_int(r | (g << 8) | (b << 16))
        dwm.DwmSetWindowAttribute(hwnd, 36, ctypes.byref(text), 4)   # DWMWA_TEXT_COLOR
    except Exception:  # noqa: BLE001 — оформление не критично
        pass


def dialog(parent: tk.Misc, title: str) -> tk.Toplevel:
    """Окно-диалог в тёмной теме."""
    top = tk.Toplevel(parent, bg=SURFACE)
    top.title(title)
    top.transient(parent)
    dark_titlebar(top, SURFACE)
    return top


def card(parent: tk.Misc, padding: int = 16) -> ttk.Frame:
    """Карточка: светлее фона окна, с тонкой рамкой."""
    outer = tk.Frame(parent, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER, bd=0)
    inner = ttk.Frame(outer, padding=padding)
    inner.pack(fill="both", expand=True)
    inner.outer = outer  # для pack/grid снаружи
    return inner


# ------------------------------------------------------------------ картинки

def _rounded(w: int, h: int, radius: int, fill: str, scale: int = 4) -> "Image.Image":
    img = Image.new("RGBA", (w * scale, h * scale), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle((0, 0, w * scale - 1, h * scale - 1), radius * scale, fill=fill)
    return img.resize((w, h), Image.LANCZOS)


def glow_dot(color: str, size: int = 52, strength: float = 1.0) -> "ImageTk.PhotoImage":
    """Светящийся индикатор: ядро и мягкое свечение вокруг."""
    scale = 4
    big = size * scale
    r, g, b = _rgb(color)
    glow = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    gr = big * 0.30
    ImageDraw.Draw(glow).ellipse((big / 2 - gr, big / 2 - gr, big / 2 + gr, big / 2 + gr),
                                 fill=(r, g, b, int(150 * strength)))
    glow = glow.filter(ImageFilter.GaussianBlur(big * 0.09))
    core = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    cr = big * 0.15
    ImageDraw.Draw(core).ellipse((big / 2 - cr, big / 2 - cr, big / 2 + cr, big / 2 + cr), fill=(r, g, b, 255))
    return ImageTk.PhotoImage(Image.alpha_composite(glow, core).resize((size, size), Image.LANCZOS))


class PillButton(tk.Label):
    """Большая скруглённая кнопка (картинка со сглаживанием + текст поверх)."""

    VARIANTS = {
        "accent": (ACCENT, ACCENT_HOVER, ACCENT_PRESS, "#ffffff"),
        "danger": ("#3a1d24", "#4a232c", "#2c161b", "#fca5a5"),
        "muted": (RAISED, RAISED, RAISED, FAINT),
    }

    def __init__(self, parent: tk.Misc, text: str, command, width: int = 200, height: int = 46,
                 variant: str = "accent", bg: str = SURFACE, font=("Segoe UI Semibold", 11)) -> None:
        super().__init__(parent, text=text, compound="center", bd=0, bg=bg, cursor="hand2", font=font)
        # не _w/_h: _w у tkinter — внутреннее имя виджета
        self._command, self._pill_w, self._pill_h = command, width, height
        self._images: dict[str, object] = {}
        self._enabled = True
        self.set_variant(variant)
        self.bind("<Enter>", lambda _e: self._show("hover"))
        self.bind("<Leave>", lambda _e: self._show("normal"))
        self.bind("<ButtonPress-1>", lambda _e: self._show("press"))
        self.bind("<ButtonRelease-1>", self._release)

    def set_variant(self, variant: str) -> None:
        self._variant = variant
        normal, hover, press, fg = self.VARIANTS[variant]
        radius = self._pill_h // 2
        images = {state: ImageTk.PhotoImage(_rounded(self._pill_w, self._pill_h, radius, color))
                  for state, color in (("normal", normal), ("hover", hover), ("press", press))}
        # сначала показать новые картинки, потом отпустить старые (иначе Tk ссылается на удалённую)
        self.configure(image=images["normal"], fg=fg)
        self._images = images
        self._show("normal")

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._show("normal")

    def _show(self, state: str) -> None:
        if not self._enabled:
            state = "normal"
        self.configure(image=self._images[state])

    def _release(self, event) -> None:
        inside = 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height()
        self._show("hover" if inside else "normal")
        if inside and self._enabled:
            self._command()

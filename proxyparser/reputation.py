"""Репутация прокси между обновлениями списка.

Каждое обновление раньше начиналось с чистого листа. Теперь программа
помнит, как каждый прокси вёл себя раньше:

* надёжность — сколько проверок из скольких он прошёл (прокси, живущий
  пятую проверку подряд, куда ценнее «случайно живого сегодня»);
* скорость и задержка — сглаженные средние по всем проверкам;
* чёрный список — прокси, пойманные на подмене сертификата, больше не
  проверяются никогда;
* «отдых» — прокси, ни разу не работавшие и упавшие много раз подряд,
  сутки не проверяются (экономит время);
* проверенные прокси перепроверяются, даже если пропали из источников;
* страна по IP кешируется, чтобы не спрашивать её повторно.

Хранится в results/reputation.json.
"""
from __future__ import annotations

import json
import logging
import pathlib
import time
from dataclasses import asdict, dataclass, field

from .models import CheckResult, Proxy, ProxyType
from .paths import APP_DIR
from .storage import write_atomic

log = logging.getLogger(__name__)

REPUTATION_FILE = APP_DIR / "results" / "reputation.json"

COOLDOWN_AFTER_FAILS = 2          # столько провалов подряд у ни разу не работавшего — на отдых
                                  # (такие почти никогда не оживают, а в больших списках их десятки тысяч)
COOLDOWN_SECONDS = 24 * 3600
PROVEN_MIN_OK = 2                 # «проверенный» — прошёл хотя бы 2 проверки...
PROVEN_MAX_AGE = 48 * 3600        # ...и работал не позже чем 48 ч назад
FORGET_AFTER = 7 * 24 * 3600      # не встречался неделю — забываем (кроме чёрного списка)
FORGET_DEAD_AFTER = 3 * 24 * 3600 # ни разу не работавшие — забываем быстрее
EMA_ALPHA = 0.4                   # вес последнего замера в сглаженных средних

MITM_MARKER = "подменяет сертификат"


@dataclass
class Entry:
    host: str
    port: int
    type: str
    source: str | None = None
    checks: int = 0
    ok: int = 0
    fail_streak: int = 0
    last_ok: float | None = None
    last_seen: float = 0.0
    latency_ms: float | None = None
    speed_kbps: float | None = None
    udp_ok: int = 0
    mitm: bool = False
    skip_until: float = 0.0

    @property
    def reliability(self) -> float:
        # сглаживание Лапласа: у новичка 0.5, а не 0 или 1
        return (self.ok + 1) / (self.checks + 2)

    def to_proxy(self) -> Proxy:
        return Proxy(host=self.host, port=self.port, type=ProxyType(self.type), source=self.source)


def _ema(old: float | None, new: float | None) -> float | None:
    if new is None:
        return old
    if old is None:
        return new
    return round(old * (1 - EMA_ALPHA) + new * EMA_ALPHA, 1)


def _key(p: Proxy) -> str:
    return f"{p.type.value}|{p.host}:{p.port}"


@dataclass
class Reputation:
    entries: dict[str, Entry] = field(default_factory=dict)
    countries: dict[str, list[str]] = field(default_factory=dict)  # ip -> [код, название]
    path: pathlib.Path = REPUTATION_FILE

    # ------------------------------------------------------------ файл

    @classmethod
    def load(cls, path: pathlib.Path | None = None) -> "Reputation":
        path = path or REPUTATION_FILE
        rep = cls(path=path)
        if not path.exists():
            return rep
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("не объект JSON")
        except (OSError, ValueError) as exc:  # ValueError: битый JSON или обрезанная кодировка
            log.warning("reputation.json не читается (%s) — начинаю с чистой репутации", exc)
            return rep
        for key, raw in data.get("entries", {}).items():
            try:
                rep.entries[key] = Entry(**raw)
            except TypeError:
                continue
        for key, raw in data.get("dead", {}).items():
            try:
                ptype, addr = key.split("|", 1)
                host, port = addr.rsplit(":", 1)
                streak, skip_until, last_seen = raw
                rep.entries[key] = Entry(host=host, port=int(port), type=ptype, checks=streak,
                                         fail_streak=streak, skip_until=skip_until, last_seen=last_seen)
            except (ValueError, TypeError):
                continue
        rep.countries = {k: v for k, v in data.get("countries", {}).items() if isinstance(v, list) and len(v) == 2}
        return rep

    def save(self) -> None:
        # Ни разу не работавшие (их в больших списках десятки тысяч) храним
        # компактно: ключ -> [провалов подряд, отдых до, когда видели].
        full, dead = {}, {}
        for k, e in self.entries.items():
            if e.ok > 0 or e.mitm:
                full[k] = asdict(e)
            else:
                dead[k] = [e.fail_streak, round(e.skip_until), round(e.last_seen)]
        payload = {
            "version": 2,
            "saved_at": time.time(),
            "entries": full,
            "dead": dead,
            "countries": self.countries,
        }
        write_atomic(self.path, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))

    # ------------------------------------------------------------ запросы

    def get(self, p: Proxy) -> Entry | None:
        return self.entries.get(_key(p))

    def should_skip(self, p: Proxy, now: float | None = None) -> str | None:
        """Причина не проверять прокси (или None)."""
        e = self.get(p)
        if e is None:
            return None
        if e.mitm:
            return "в чёрном списке: подменял сертификат"
        if e.skip_until > (now or time.time()):
            return "на отдыхе: много раз подряд не работал"
        return None

    def proven(self, now: float | None = None) -> list[Proxy]:
        now = now or time.time()
        out = []
        for e in self.entries.values():
            if e.mitm or e.ok < PROVEN_MIN_OK or e.last_ok is None:
                continue
            if now - e.last_ok <= PROVEN_MAX_AGE:
                out.append(e.to_proxy())
        return out

    def country_of(self, host: str) -> tuple[str, str] | None:
        v = self.countries.get(host)
        return (v[0], v[1]) if v else None

    def remember_countries(self, found: dict[str, tuple[str, str]]) -> None:
        for ip, (code, name) in found.items():
            self.countries[ip] = [code, name]

    def annotate(self, r: CheckResult) -> None:
        """Дописать в результат надёжность из истории (для таблицы и выбора)."""
        e = self.get(r.proxy)
        if e is not None:
            r.rep_ok, r.rep_checks = e.ok, e.checks

    # ------------------------------------------------------------ обновление

    def update(self, results: list[CheckResult], now: float | None = None) -> None:
        now = now or time.time()
        for r in results:
            p = r.proxy
            key = _key(p)
            e = self.entries.get(key) or Entry(host=p.host, port=p.port, type=p.type.value, source=p.source)
            e.last_seen = now
            if p.source and not e.source:
                e.source = p.source
            e.checks += 1
            if r.working:
                e.ok += 1
                e.fail_streak = 0
                e.last_ok = now
                e.skip_until = 0.0
                e.latency_ms = _ema(e.latency_ms, r.latency_ms)
                e.speed_kbps = _ema(e.speed_kbps, r.speed_kbps)
                e.udp_ok += 1 if r.udp else 0
            else:
                e.fail_streak += 1
                if r.error and MITM_MARKER in r.error:
                    e.mitm = True
                if e.ok == 0 and e.fail_streak >= COOLDOWN_AFTER_FAILS:
                    e.skip_until = now + COOLDOWN_SECONDS
            self.entries[key] = e
            r.rep_ok, r.rep_checks = e.ok, e.checks

    def prune(self, now: float | None = None) -> int:
        now = now or time.time()
        stale = [k for k, e in self.entries.items()
                 if not e.mitm and now - e.last_seen > (FORGET_AFTER if e.ok else FORGET_DEAD_AFTER)]
        for k in stale:
            del self.entries[k]
        return len(stale)

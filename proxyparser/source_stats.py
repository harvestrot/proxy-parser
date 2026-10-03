"""Статистика источников: откуда приходят действительно хорошие прокси.

После каждого обновления для каждого источника считается: сколько прокси он
дал, сколько из них живы (порт открыт), сколько прошли полную проверку,
сколько быстрых (замеренная скорость от 500 КБ/с), сколько в сетях обычных
провайдеров, а не хостингов (их ТСПУ не душит — см. geo.py), и
сколько рабочих есть ТОЛЬКО у него (уникальный вклад). Если один прокси есть в
нескольких списках, он засчитывается каждому из них.

Итоги копятся в results/source_stats.json (последние запуски + суммы), чтобы
решать, какие источники оставить, не по одному случайному запуску.
"""
from __future__ import annotations

import json
import pathlib
import time
from dataclasses import asdict, dataclass

from . import checker, filters, geo, singbox_config, storage
from .models import CheckResult
from .paths import APP_DIR

STATS_FILE = APP_DIR / "results" / "source_stats.json"
FAST_KBPS = singbox_config.GOOD_SPEED_KBPS  # «быстрый» — тот же порог, что и для группы VPN
KEEP_RUNS = 30


@dataclass
class SourceRow:
    listed: int = 0
    alive: int = 0
    working: int = 0
    fast: int = 0
    isp: int = 0  # рабочих в сети провайдера или мобильной (не хостинг)
    unique_working: int = 0

    @property
    def working_pct(self) -> float:
        return 100.0 * self.working / self.listed if self.listed else 0.0


def compute(members: dict[str, list[str]], results: list[CheckResult]) -> dict[str, SourceRow]:
    by_addr = {r.proxy.address: r for r in results}
    working_sources: dict[str, set[str]] = {}
    for name, addrs in members.items():
        for a in set(addrs):
            r = by_addr.get(a)
            if r is not None and r.working:
                working_sources.setdefault(a, set()).add(name)

    rows: dict[str, SourceRow] = {}
    for name, addrs in members.items():
        row = SourceRow()
        for a in set(addrs):
            row.listed += 1
            r = by_addr.get(a)
            if r is None:
                continue  # не проверялся (чёрный список / отдых)
            if r.error not in (checker.PREFILTER_DEAD_REASON, filters.EXCLUDE_REASON):
                row.alive += 1
            if r.working:
                row.working += 1
                row.fast += (r.speed_kbps or 0) >= FAST_KBPS
                row.isp += r.proxy.network in (geo.NET_ISP, geo.NET_MOBILE)
                row.unique_working += working_sources.get(a) == {name}
        rows[name] = row
    return rows


def format_table(rows: dict[str, SourceRow]) -> list[str]:
    lines = ["Источник                  дал   живых  рабочих  быстрых  у провайдера  уникальных  % рабочих"]
    for name, r in sorted(rows.items(), key=lambda kv: (-kv[1].fast, -kv[1].working)):
        lines.append(f"{name[:24]:24} {r.listed:5} {r.alive:7} {r.working:8} {r.fast:8} {r.isp:13}"
                     f" {r.unique_working:11} {r.working_pct:9.1f}")
    return lines


def save(rows: dict[str, SourceRow], path: pathlib.Path | None = None) -> dict:
    path = path or STATS_FILE
    data = (storage.read_json(path) if path.exists() else None) or {"runs": [], "totals": {}}
    data.setdefault("runs", []).append({"at": time.time(), "sources": {k: asdict(v) for k, v in rows.items()}})
    data["runs"] = data["runs"][-KEEP_RUNS:]
    totals = data.setdefault("totals", {})
    for name, row in rows.items():
        t = totals.setdefault(name, {"runs": 0, **{k: 0 for k in asdict(SourceRow())}})
        t["runs"] += 1
        for k, v in asdict(row).items():
            t[k] = t.get(k, 0) + v
    storage.write_atomic(path, json.dumps(data, ensure_ascii=False, indent=1))
    return totals

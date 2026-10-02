"""Конвейер обновления списка: от сырых прокси из источников до проверенных.

    источники + проверенные из репутации
      -> чёрный список и «отдых» из репутации (не проверяем)
      -> страна из источника / кеша; прокси из РФ отсеиваются
      -> быстрый отсев: открыт ли порт (за секунды убирает 80–90%)
      -> полная проверка: HTTPS через прокси + сертификаты + UDP
      -> страна по IP (ip-api) для рабочих без страны; РФ исключается
      -> замер реальной скорости у рабочих
      -> обновление репутации
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from . import checker, filters, geo
from .models import CheckResult, Proxy
from .reputation import Reputation

log = logging.getLogger(__name__)

# on_stage(название_этапа, сделано, всего)
StageCallback = Callable[[str, int, int], None]


@dataclass
class PipelineStats:
    from_sources: int = 0
    from_reputation: int = 0
    skipped_by_reputation: int = 0
    excluded_country: int = 0
    prefilter_dead: int = 0
    full_checked: int = 0
    working: int = 0
    udp: int = 0
    speed_measured: int = 0
    notes: list[str] = field(default_factory=list)


def _apply_known_countries(proxies: list[Proxy], rep: Reputation) -> list[Proxy]:
    """Заполнить страну из кеша; вернуть те, у кого страна всё ещё неизвестна."""
    unknown = []
    for p in proxies:
        if p.country_code:
            rep.remember_countries({p.host: (p.country_code, p.country or "")})
            continue
        cached = rep.country_of(p.host)
        if cached:
            p.country_code, p.country = cached[0] or None, cached[1] or None
        else:
            unknown.append(p)
    return unknown


async def run(
    proxies: list[Proxy],
    rep: Reputation,
    *,
    timeout: float = checker.DEFAULT_TIMEOUT_S,
    concurrency: int = checker.DEFAULT_CONCURRENCY,
    on_stage: StageCallback | None = None,
    lookup_countries=None,
    check_kwargs: dict | None = None,
    speed_kwargs: dict | None = None,
    prefilter_kwargs: dict | None = None,
) -> tuple[list[CheckResult], PipelineStats]:
    stage = on_stage or (lambda *_: None)
    lookup = lookup_countries or geo.lookup_countries
    stats = PipelineStats(from_sources=len(proxies))
    now = time.time()
    results: list[CheckResult] = []

    # 1. добавить проверенные прокси из репутации, которых нет в источниках
    known = {(p.host, p.port) for p in proxies}
    extra = [p for p in rep.proven(now) if (p.host, p.port) not in known]
    stats.from_reputation = len(extra)
    candidates = proxies + extra

    # 2. чёрный список / отдых
    to_check: list[Proxy] = []
    for p in candidates:
        if rep.should_skip(p, now):
            stats.skipped_by_reputation += 1
        else:
            to_check.append(p)

    # 3. страны, известные заранее (источник или кеш), и исключение РФ
    _apply_known_countries(to_check, rep)

    def split_excluded(items: list[Proxy]) -> list[Proxy]:
        keep = []
        for p in items:
            if filters.is_excluded(p):
                stats.excluded_country += 1
                results.append(CheckResult(p, False, error=filters.EXCLUDE_REASON, checked_at=now))
            else:
                keep.append(p)
        return keep

    to_check = split_excluded(to_check)

    # 4. быстрый отсев по открытому порту
    stage("Быстрый отсев мёртвых", 0, len(to_check))
    alive, dead = await checker.prefilter(
        to_check, on_progress=lambda d, t: stage("Быстрый отсев мёртвых", d, t), **(prefilter_kwargs or {}))
    stats.prefilter_dead = len(dead)
    if to_check and not alive:
        # ни один порт не открылся — скорее всего, нет интернета; репутацию не портим
        raise RuntimeError("ни один прокси не ответил даже на подключение — проверь интернет")
    results += [CheckResult(p, False, error=checker.PREFILTER_DEAD_REASON, checked_at=now) for p in dead]

    # 5. полная проверка
    stats.full_checked = len(alive)
    full = await checker.check_all(
        alive, timeout=timeout, concurrency=concurrency,
        on_progress=lambda d, t, _r: stage("Проверка прокси", d, t), **(check_kwargs or {}))

    # 6. страна для РАБОЧИХ, у кого её не было (бесплатный гео-API ограничен
    #    ~1500 IP за раз — тратим его только на тех, кто реально нужен);
    #    оказавшиеся в РФ исключаются
    need_geo = [r.proxy for r in full if r.working and not r.proxy.country_code]
    if need_geo:
        stage("Определяю страны", 0, len(need_geo))
        found = lookup([p.host for p in need_geo])
        rep.remember_countries(found)
        for p in need_geo:
            if p.host in found:
                p.country_code, p.country = found[p.host][0] or None, found[p.host][1] or None
        stage("Определяю страны", len(need_geo), len(need_geo))
        for r in full:
            if r.working and filters.is_excluded(r.proxy):
                r.working, r.error = False, filters.EXCLUDE_REASON
                stats.excluded_country += 1
    results += full
    working = [r for r in full if r.working]
    stats.working = len(working)
    stats.udp = sum(1 for r in working if r.udp)

    # 7. скорость у рабочих
    if working:
        stats.speed_measured = await checker.measure_top_speeds(
            full, on_progress=lambda d, t, _r: stage("Замер скорости", d, t), **(speed_kwargs or {}))

    # 8. репутация
    # (исключённые по стране не проверялись — их в репутацию не пишем)
    rep.update([r for r in results if r.error != filters.EXCLUDE_REASON], now)
    for r in results:
        rep.annotate(r)
    forgotten = rep.prune(now)
    if forgotten:
        stats.notes.append(f"забыто давно не встречавшихся прокси: {forgotten}")
    return results, stats

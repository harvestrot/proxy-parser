"""Сохранение/загрузка результатов проверки прокси в JSON."""
from __future__ import annotations

import json
import logging
import os
import pathlib
import time

from .filters import is_excluded
from .models import CheckResult, Proxy, ProxyType
from .paths import APP_DIR

log = logging.getLogger(__name__)

RESULTS_DIR = APP_DIR / "results"
WORKING_PROXIES_FILE = RESULTS_DIR / "working_proxies.json"
ALL_PROXIES_FILE = RESULTS_DIR / "all_proxies.json"
_KNOWN_TYPES = {t.value for t in ProxyType}


def write_atomic(path: pathlib.Path, text: str) -> None:
    """Записать файл так, чтобы на диске всегда был либо старый, либо новый
    целый вариант: пишем во временный файл, сбрасываем на диск и подменяем.
    Обычная запись при отключении света посреди неё оставляет обрезанный
    JSON — и программа потом не может его прочитать."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_json(path: pathlib.Path) -> dict | None:
    """Прочитать JSON; испорченный файл — предупреждение и None, а не падение."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # ValueError: битый JSON или кодировка
        log.warning("%s не читается (%s) — начинаю без него", path.name, exc)
        return None
    return data if isinstance(data, dict) else None


def save_scraped(proxies: list[Proxy], path: pathlib.Path | None = None) -> None:
    path = path or ALL_PROXIES_FILE
    payload = {
        "scraped_at": time.time(),
        "total": len(proxies),
        "proxies": [p.to_dict() for p in proxies],
    }
    write_atomic(path, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def load_scraped(path: pathlib.Path | None = None) -> list[Proxy]:
    path = path or ALL_PROXIES_FILE
    if not path.exists():
        return []
    data = read_json(path) or {}
    out = []
    for item in data.get("proxies", []):
        if item.get("type") not in _KNOWN_TYPES:
            continue  # например, записи старых версий с неизвестным типом
        out.append(
            Proxy(
                host=item["host"],
                port=item["port"],
                type=ProxyType(item["type"]),
                country=item.get("country"),
                anonymity=item.get("anonymity"),
                source_latency_ms=item.get("source_latency_ms"),
                source=item.get("source"),
                country_code=item.get("country_code"),
            )
        )
    return out


def save_results(results: list[CheckResult], path: pathlib.Path | None = None) -> None:
    path = path or WORKING_PROXIES_FILE
    # Храним только рабочие (+ сводку причин отказа): раньше сюда писались
    # все проверенные — при больших источниках файл раздувался до 70+ МБ.
    errors: dict[str, int] = {}
    for r in results:
        if not r.working:
            reason = (r.error or "неизвестно").split(":")[0][:60]
            errors[reason] = errors.get(reason, 0) + 1
    payload = {
        "generated_at": time.time(),
        "total_checked": len(results),
        "total_working": sum(1 for r in results if r.working),
        "failure_reasons": dict(sorted(errors.items(), key=lambda kv: -kv[1])),
        "proxies": [r.to_dict() for r in results if r.working],
    }
    write_atomic(path, json.dumps(payload, ensure_ascii=False, indent=1))


def load_working_proxies(path: pathlib.Path | None = None) -> list[CheckResult]:
    path = path or WORKING_PROXIES_FILE
    if not path.exists():
        return []
    # испорченный файл — пустой список (кнопка «Обновить список» соберёт новый),
    # а не падение окна при запуске
    data = read_json(path) or {}
    out: list[CheckResult] = []
    for item in data.get("proxies", []):
        if item.get("type") not in _KNOWN_TYPES:
            continue  # например, записи старых версий с неизвестным типом
        if not item.get("working"):
            continue
        proxy = Proxy(
            host=item["host"],
            port=item["port"],
            type=ProxyType(item["type"]),
            country=item.get("country"),
            anonymity=item.get("anonymity"),
            source_latency_ms=item.get("source_latency_ms"),
            source=item.get("source"),
            country_code=item.get("country_code"),
            network=item.get("network"),
            asn=item.get("asn"),
        )
        if is_excluded(proxy):
            continue  # например, сохранено до появления фильтра по странам
        out.append(
            CheckResult(
                proxy=proxy,
                working=True,
                latency_ms=item.get("latency_ms"),
                checked_at=item.get("checked_at", 0.0),
                udp_ms=item.get("udp_ms"),
                speed_kbps=item.get("speed_kbps"),
                rep_ok=item.get("rep_ok", 0),
                rep_checks=item.get("rep_checks", 0),
            )
        )
    return out


def sorted_by_priority(results: list[CheckResult]) -> list[CheckResult]:
    """SOCKS5 -> SOCKS4 -> HTTPS, внутри типа — по задержке (меньше лучше)."""

    def key(r: CheckResult):
        latency = r.latency_ms if r.latency_ms is not None else float("inf")
        return (r.proxy.type.priority, latency)

    return sorted((r for r in results if r.working), key=key)

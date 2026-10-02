"""Определение страны по IP — для списков, где страна не указана.

Нужна для двух вещей: отсеять прокси из РФ и учитывать географию (из РФ
ближняя Европа обычно быстрее, чем Юго-Восточная Азия или Латинская Америка).

Используется бесплатный batch-API ip-api.com: до 100 IP за запрос, до 15
запросов в минуту (некоммерческое использование). Страны кешируются в
репутации, так что повторно одни и те же IP не спрашиваем.
"""
from __future__ import annotations

import logging
from typing import Callable

import requests

log = logging.getLogger(__name__)

IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,country,query"
BATCH_SIZE = 100
MAX_BATCHES = 15  # лимит бесплатного API — 15 запросов в минуту

Poster = Callable[[str, list], list]

# Ближе к РФ по сети — обычно ниже задержка и выше скорость.
NEAR_COUNTRIES = {
    "FI", "EE", "LV", "LT", "PL", "DE", "NL", "SE", "NO", "DK", "CZ", "SK", "AT", "CH",
    "FR", "BE", "LU", "GB", "IE", "HU", "RO", "BG", "MD", "TR", "GE", "AM", "AZ", "KZ",
    "RS", "HR", "SI", "IT", "ES", "PT", "GR", "CY", "IS",
}
# Далеко — пинг из РФ почти всегда больше секунды.
FAR_COUNTRIES = {
    "BR", "AR", "CL", "CO", "PE", "MX", "VE", "EC", "BO", "PY", "UY", "ZA", "NG", "KE",
    "EG", "AU", "NZ", "ID", "PH", "VN", "TH", "MY", "SG", "KH", "BD", "PK", "IN", "CN",
    "HK", "TW", "JP", "KR",
}


def geo_factor(country_code: str | None) -> float:
    if not country_code:
        return 1.0
    code = country_code.upper()
    if code in NEAR_COUNTRIES:
        return 1.25
    if code in FAR_COUNTRIES:
        return 0.8
    return 1.0


def _default_post(url: str, payload: list) -> list:
    resp = requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def lookup_countries(ips: list[str], post: Poster | None = None) -> dict[str, tuple[str, str]]:
    """{ip: (код, название)} для тех IP, что удалось определить."""
    post = post or _default_post
    unique = list(dict.fromkeys(ips))
    out: dict[str, tuple[str, str]] = {}
    batches = [unique[i:i + BATCH_SIZE] for i in range(0, len(unique), BATCH_SIZE)]
    if len(batches) > MAX_BATCHES:
        log.info("Стран нужно определить для %d IP — за раз успею %d, остальные в следующий раз",
                 len(unique), MAX_BATCHES * BATCH_SIZE)
        batches = batches[:MAX_BATCHES]
    for batch in batches:
        try:
            data = post(IP_API_BATCH_URL, batch)
        except Exception as exc:  # noqa: BLE001 — гео не критично, без него просто хуже сортировка
            log.info("Определение стран не удалось (%s) — продолжаю без него", exc)
            break
        for item in data or []:
            if isinstance(item, dict) and item.get("status") == "success" and item.get("query"):
                out[item["query"]] = (item.get("countryCode") or "", item.get("country") or "")
    return out

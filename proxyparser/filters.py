"""Правила исключения прокси, которые нам заведомо не нужны.

Сейчас одно правило: прокси, находящиеся в России, — смысла в них нет
(трафик всё равно остаётся в РФ, под теми же блокировками). Такие прокси
помечаются нерабочими сразу, без сетевой проверки, и выбрасываются из
ранее сохранённых списков.
"""
from __future__ import annotations

from .models import Proxy

EXCLUDED_COUNTRY_CODES = {"RU"}
EXCLUDED_COUNTRY_NAMES = {"russia", "russian federation", "россия", "российская федерация"}
EXCLUDE_REASON = "прокси в России — исключён"


def is_excluded(proxy: Proxy) -> bool:
    if proxy.country_code and proxy.country_code.upper() in EXCLUDED_COUNTRY_CODES:
        return True
    return bool(proxy.country) and proxy.country.strip().lower() in EXCLUDED_COUNTRY_NAMES

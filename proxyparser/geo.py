"""Страна и тип сети по IP.

Страна нужна для двух вещей: отсеять прокси из РФ и учитывать географию (из
РФ ближняя Европа обычно быстрее, чем Юго-Восточная Азия или Латинская
Америка).

Тип сети — хостинг (дата-центр) или обычный провайдер. ТСПУ душит трафик к
зарубежным хостингам (Hetzner, OVH, DigitalOcean, Amazon, Oracle…:
соединение «замирает» после ~16 КБ), а к сетям обычных провайдеров — нет. По
замеру 2 октября 2026 у рабочих прокси в сетях провайдеров медианная
скорость ~2 МБ/с, у хостинговых — ~70 КБ/с (лучшие находки — шведские
HTTPS-прокси у провайдера Bredband2 — как раз такие).

Используется бесплатный batch-API ip-api.com: до 100 IP за запрос, до 15
запросов в минуту (некоммерческое использование). Страна и сеть приходят в
одном ответе и кешируются в репутации, так что повторно одни и те же IP не
спрашиваем.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

import requests

log = logging.getLogger(__name__)

IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,country,hosting,mobile,as,query"

# Тип сети прокси (Proxy.network)
NET_ISP = "isp"          # обычный провайдер (домашний/офисный интернет)
NET_MOBILE = "mobile"    # мобильный оператор
NET_HOSTING = "hosting"  # хостинг / дата-центр / облако
NETWORK_LABELS = {NET_ISP: "провайдер", NET_MOBILE: "мобильная", NET_HOSTING: "хостинг"}

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


# Скорость и так замеряется, поэтому множитель умеренный: он решает при
# близкой скорости и у незамеренных. Хостинг не штрафуется сильнее — среди
# них бывают быстрые (Google Cloud в Финляндии — 6 МБ/с), но ТСПУ может
# придушить их в любой момент, а провайдерские сети он не трогает.
NETWORK_FACTOR = {NET_ISP: 1.2, NET_MOBILE: 1.2, NET_HOSTING: 0.9}


def network_factor(network: str | None) -> float:
    return NETWORK_FACTOR.get(network or "", 1.0)


@dataclass(frozen=True)
class IpInfo:
    country_code: str = ""
    country: str = ""
    network: str | None = None  # NET_ISP / NET_MOBILE / NET_HOSTING
    asn: str = ""               # «AS29518 Bredband2 AB»


def _network_of(item: dict) -> str | None:
    if item.get("mobile") is True:
        return NET_MOBILE
    if item.get("hosting") is True:
        return NET_HOSTING
    if item.get("hosting") is False:
        return NET_ISP
    return None


def _default_post(url: str, payload: list) -> list:
    resp = requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def lookup_ips(ips: list[str], post: Poster | None = None) -> dict[str, IpInfo]:
    """{ip: IpInfo} для тех IP, что удалось определить."""
    post = post or _default_post
    unique = list(dict.fromkeys(ips))
    out: dict[str, IpInfo] = {}
    batches = [unique[i:i + BATCH_SIZE] for i in range(0, len(unique), BATCH_SIZE)]
    if len(batches) > MAX_BATCHES:
        log.info("Страну и сеть нужно определить для %d IP — за раз успею %d, остальные в следующий раз",
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
                out[item["query"]] = IpInfo(
                    country_code=item.get("countryCode") or "", country=item.get("country") or "",
                    network=_network_of(item), asn=str(item.get("as") or "")[:60])
    return out

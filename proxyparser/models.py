"""Общие структуры данных проекта."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum


class ProxyType(str, Enum):
    """Тип прокси в порядке приоритета (меньше — приоритетнее)."""

    SOCKS5 = "SOCKS5"
    SOCKS4 = "SOCKS4"
    HTTPS = "HTTPS"

    @property
    def priority(self) -> int:
        return _PRIORITY[self.value]


_PRIORITY = {"SOCKS5": 0, "SOCKS4": 1, "HTTPS": 2}


@dataclass
class Proxy:
    """Один прокси, спарсенный с сайта-источника."""

    host: str
    port: int
    type: ProxyType
    country: str | None = None
    anonymity: str | None = None
    source_latency_ms: int | None = None  # скорость, которую заявил сайт-источник
    source: str | None = None  # откуда взят, например "proxyscrape.com"
    country_code: str | None = None  # ISO-код страны, например "DE"

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d

    def __hash__(self) -> int:
        return hash((self.host, self.port, self.type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Proxy):
            return NotImplemented
        return (self.host, self.port, self.type) == (other.host, other.port, other.type)


@dataclass
class CheckResult:
    """Результат проверки прокси на рабочесть."""

    proxy: Proxy
    working: bool
    latency_ms: float | None = None
    error: str | None = None
    checked_at: float = 0.0
    udp_ms: float | None = None      # задержка UDP через прокси; None — UDP не поддерживается/не проверялся
    speed_kbps: float | None = None  # реальная скорость скачивания, КБ/с (замеряется у лучших)
    rep_ok: int = 0                  # из репутации: сколько проверок прошёл за всё время...
    rep_checks: int = 0              # ...из скольких

    @property
    def reliability(self) -> float:
        return (self.rep_ok + 1) / (self.rep_checks + 2)

    @property
    def udp(self) -> bool:
        return self.udp_ms is not None

    def to_dict(self) -> dict:
        return {
            **self.proxy.to_dict(),
            "working": self.working,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "checked_at": self.checked_at,
            "udp_ms": self.udp_ms,
            "speed_kbps": self.speed_kbps,
            "rep_ok": self.rep_ok,
            "rep_checks": self.rep_checks,
        }

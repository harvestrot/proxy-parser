"""Проверка прокси на рабочесть.

Прокси считается рабочим, только если через него реально прошёл HTTPS-
запрос: туннель -> TLS-рукопожатие с проверкой сертификата -> ответ
``204`` от тестовой страницы. Одного «соединение установлено» от прокси
мало: многие бесплатные прокси так отвечают, но данные дальше не
передают (или подменяют сертификат — такие тоже отсеиваются).

Тестовая страница та же, что у sing-box при выборе прокси
(``generate_204``), — чтобы наша проверка и VPN оценивали одно и то же.
Время отклика — полное время от подключения до ответа.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass

from .filters import EXCLUDE_REASON, is_excluded
from . import quality
from .models import CheckResult, Proxy, ProxyType
from .scraper import subnet24
from .upstream import UpstreamError, UpstreamUnreachable, connect_via

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProbeTarget:
    host: str
    port: int
    tls: bool
    path: str = "/generate_204"


DEFAULT_PROBES: tuple[ProbeTarget, ...] = (
    ProbeTarget("www.gstatic.com", 443, True),
    ProbeTarget("cp.cloudflare.com", 443, True),
)

# Обязательные проверки сверх основной. Через выбранный прокси VPN ходит в
# DNS-over-HTTPS по адресу 1.1.1.1 — встречаются прокси, которые
# «выборочно» подменяют сертификат именно там (сайты при этом проходят).
# Такой прокси ломает DNS и вообще опасен, поэтому сертификат 1.1.1.1
# тоже проверяем, и без этого прокси не считается рабочим.
DEFAULT_REQUIRED_PROBES: tuple[ProbeTarget, ...] = (
    ProbeTarget("1.1.1.1", 443, True, "/cdn-cgi/trace"),
)

DEFAULT_TIMEOUT_S = 6.0
DEFAULT_CONCURRENCY = 300


class ProxyCheckError(Exception):
    pass


_SSL_CTX = ssl.create_default_context()

# Всё, что означает «через этот прокси не вышло» (ValueError — в т.ч.
# UnicodeError и слишком длинная строка ответа в readline).
_PROBE_ERRORS = (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ssl.SSLError,
                 UpstreamError, ProxyCheckError, ValueError)


async def _probe(proxy: Proxy, target: ProbeTarget, timeout: float) -> None:
    reader, writer = await connect_via(proxy, target.host, target.port, timeout)
    try:
        if target.tls:
            if not hasattr(writer, "start_tls"):  # Python < 3.11
                raise ProxyCheckError("нужен Python 3.11+ для TLS-проверки")
            await asyncio.wait_for(
                writer.start_tls(_SSL_CTX, server_hostname=target.host), timeout=timeout
            )
        request = (
            f"GET {target.path} HTTP/1.1\r\n"
            f"Host: {target.host}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        parts = status_line.split()
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or parts[1] not in (b"204", b"200"):
            raise ProxyCheckError(f"неожиданный ответ: {status_line[:60]!r}")
    finally:
        writer.close()


async def _check_as(
    proxy: Proxy, probes: tuple[ProbeTarget, ...], timeout: float
) -> tuple[CheckResult, bool]:
    """Проверить прокси как прокси его (известного) типа.
    Возвращает (результат, был_ли_прокси_вообще_доступен_по_TCP)."""
    last_error: str | None = None
    reachable = False
    for target in probes:
        start = time.monotonic()
        try:
            # общий потолок на одну попытку: туннель + TLS + ответ
            await asyncio.wait_for(_probe(proxy, target, timeout), timeout=timeout * 2)
            latency_ms = (time.monotonic() - start) * 1000
            return CheckResult(proxy=proxy, working=True, latency_ms=round(latency_ms, 1), checked_at=time.time()), True
        except UpstreamUnreachable as exc:
            # до прокси даже не достучались — пробовать другие цели бессмысленно
            return CheckResult(proxy=proxy, working=False, error=str(exc), checked_at=time.time()), False
        except _PROBE_ERRORS as exc:
            reachable = True
            last_error = str(exc) or type(exc).__name__
            continue
    return CheckResult(proxy=proxy, working=False, error=last_error, checked_at=time.time()), reachable


async def check_proxy(
    proxy: Proxy,
    *,
    probes: tuple[ProbeTarget, ...] = DEFAULT_PROBES,
    required_probes: tuple[ProbeTarget, ...] = DEFAULT_REQUIRED_PROBES,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> CheckResult:
    result, _ = await _check_as(proxy, probes, timeout)
    if not result.working:
        return result
    for target in required_probes:
        try:
            await asyncio.wait_for(_probe(proxy, target, timeout), timeout=timeout * 2)
        except _PROBE_ERRORS as exc:
            reason = str(exc) or type(exc).__name__
            if "CERTIFICATE" in reason.upper():
                reason = f"подменяет сертификат ({target.host}) — опасен: {reason}"
            return CheckResult(proxy=proxy, working=False, error=reason, checked_at=time.time())
    return result


async def check_all(
    proxies: list[Proxy],
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT_S,
    probes: tuple[ProbeTarget, ...] = DEFAULT_PROBES,
    on_progress=None,
    required_probes: tuple[ProbeTarget, ...] = DEFAULT_REQUIRED_PROBES,
    check_udp_support: bool = True,
    udp_target: tuple[str, int] | None = None,  # None — штатные цели (quality.UDP_TEST_TARGETS)
) -> list[CheckResult]:
    """Проверить список прокси параллельно (с ограничением конкурентности).
    У рабочих SOCKS5 заодно проверяется поддержка UDP (нужна для звонков)."""

    sem = asyncio.Semaphore(concurrency)
    results: list[CheckResult] = []
    done_count = 0
    total = len(proxies)

    async def _one(p: Proxy) -> None:
        nonlocal done_count
        if is_excluded(p):
            # заведомо не нужен — помечаем нерабочим без сетевой проверки
            res = CheckResult(proxy=p, working=False, error=EXCLUDE_REASON, checked_at=time.time())
        else:
            async with sem:
                try:
                    res = await check_proxy(p, probes=probes, required_probes=required_probes, timeout=timeout)
                    if res.working and check_udp_support and p.type == ProxyType.SOCKS5:
                        res.udp_ms = await quality.check_udp(p, timeout=min(timeout, 5.0), target=udp_target)
                except Exception as exc:  # noqa: BLE001 — сбой одного прокси не должен ронять всю проверку
                    log.debug("Проверка %s упала: %r", p.address, exc)
                    res = CheckResult(proxy=p, working=False, error=f"сбой проверки: {exc!r}"[:200],
                                      checked_at=time.time())
        results.append(res)
        done_count += 1
        if on_progress is not None:
            on_progress(done_count, total, res)

    await asyncio.gather(*(_one(p) for p in proxies))
    return results


SPEED_TEST_TOP = 300         # замеряем практически всех рабочих: прокси без замера в VPN
                             # идут лишь в крайнем случае, а медленные — не идут вовсе
SPEED_TEST_PER_SUBNET = 2    # в первую очередь — не больше стольких из одной подсети /24
                             # (столько же из неё берёт VPN), остальные — если хватит мест
SPEED_TEST_CONCURRENCY = 10  # немного параллельно — чтобы не упереться в свой же канал
                             # (иначе замер покажет нашу скорость, а не прокси)


async def measure_top_speeds(
    results: list[CheckResult],
    *,
    top: int = SPEED_TEST_TOP,
    concurrency: int = SPEED_TEST_CONCURRENCY,
    target: "quality.SpeedTarget | None" = None,
    on_progress=None,
) -> int:
    """Замерить реальную скорость у ``top`` самых быстрых по задержке рабочих
    прокси (результаты дополняются на месте). Возвращает, сколько замерено.

    Места распределяются по подсетям: сначала не больше
    SPEED_TEST_PER_SUBNET лучших из каждой /24, потом остальные. Иначе
    десятки рабочих портов одной «фермы» с малой задержкой занимают весь
    замер, а прокси из других сетей остаются без скорости — и в VPN не
    попадают."""
    by_latency = sorted(
        (r for r in results if r.working),
        # по задержке, тип не важен: в основную группу VPN теперь попадают
        # и быстрые HTTPS-прокси
        key=lambda r: r.latency_ms if r.latency_ms is not None else float("inf"),
    )
    first, rest = [], []
    per_net: dict[str, int] = {}
    for r in by_latency:
        net = subnet24(r.proxy.host)
        per_net[net] = per_net.get(net, 0) + 1
        (first if per_net[net] <= SPEED_TEST_PER_SUBNET else rest).append(r)
    candidates = (first + rest)[:top]
    sem = asyncio.Semaphore(concurrency)
    done = 0
    measured = 0

    async def _one(r: CheckResult) -> None:
        nonlocal done, measured
        async with sem:
            kwargs = {"target": target} if target is not None else {}
            try:
                r.speed_kbps = await quality.measure_speed(r.proxy, **kwargs)
            except Exception as exc:  # noqa: BLE001 — замер не критичен, без него просто нет скорости
                log.debug("Замер скорости %s упал: %r", r.proxy.address, exc)
                r.speed_kbps = None
        done += 1
        measured += r.speed_kbps is not None
        if on_progress is not None:
            on_progress(done, len(candidates), r)

    await asyncio.gather(*(_one(r) for r in candidates))
    return measured


# ------------------------------------------------------------ быстрый отсев

PREFILTER_TIMEOUT_S = 2.0
PREFILTER_CONCURRENCY = 500
PREFILTER_DEAD_REASON = "порт закрыт или не отвечает"


async def tcp_alive(proxy: Proxy, timeout: float = PREFILTER_TIMEOUT_S) -> bool:
    """Самая дешёвая проверка: открывается ли TCP-соединение с прокси."""
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy.host, proxy.port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    return True


async def prefilter(
    proxies: list[Proxy],
    *,
    concurrency: int = PREFILTER_CONCURRENCY,
    timeout: float = PREFILTER_TIMEOUT_S,
    on_progress=None,
) -> tuple[list[Proxy], list[Proxy]]:
    """Отсеять заведомо мёртвые (порт не открывается) — это 80–90% бесплатных
    списков. Возвращает (живые, мёртвые). Полную проверку дальше проходят
    только живые — так можно подключать списки на тысячи прокси."""
    sem = asyncio.Semaphore(concurrency)
    alive: list[Proxy] = []
    dead: list[Proxy] = []
    done = 0

    async def _one(p: Proxy) -> None:
        nonlocal done
        async with sem:
            ok = await tcp_alive(p, timeout)
        (alive if ok else dead).append(p)
        done += 1
        if on_progress is not None:
            on_progress(done, len(proxies))

    await asyncio.gather(*(_one(p) for p in proxies))
    return alive, dead

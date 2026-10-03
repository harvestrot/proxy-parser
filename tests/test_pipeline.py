"""Сквозной тест конвейера обновления на локальных фейковых прокси.

Набор: честный SOCKS5, мёртвый порт, прокси из РФ (страна из источника),
прокси без страны (ip-api «скажет», что он из РФ), прокси из чёрного
списка репутации и «проверенный» прокси из репутации, которого нет в
источниках.
"""
import asyncio
import pathlib
import socket
import struct
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import checker, geo, pipeline, quality  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402
from proxyparser.reputation import Reputation  # noqa: E402


async def pipe(a, b):
    try:
        while True:
            c = await a.read(65536)
            if not c:
                break
            b.write(c)
            await b.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        b.close()


async def socks5(reader, writer):
    await reader.readexactly(2)
    await reader.readexactly(1)
    writer.write(b"\x05\x00")
    head = await reader.readexactly(4)
    if head[3] == 1:
        host = socket.inet_ntoa(await reader.readexactly(4))
    else:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode()
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    if head[1] != 1:  # UDP не поддерживаем
        writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
        writer.close()
        return
    writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
    await writer.drain()
    tr, tw = await asyncio.open_connection(host, port)
    await asyncio.gather(pipe(reader, tw), pipe(tr, writer))


async def target(reader, writer):
    req = await reader.readline()
    while (await reader.readline()) not in (b"\r\n", b""):
        pass
    if b"/big" in req:
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 400_000)
    else:
        writer.write(b"HTTP/1.1 204 No Content\r\n\r\n")
    await writer.drain()
    writer.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def main():
    t_srv = await asyncio.start_server(target, "127.0.0.1", 0)
    t_port = t_srv.sockets[0].getsockname()[1]
    servers = [await asyncio.start_server(socks5, "0.0.0.0", 0) for _ in range(5)]  # 0.0.0.0 — чтобы отвечал и 127.0.0.2
    ports = [s.sockets[0].getsockname()[1] for s in servers]

    good = Proxy("127.0.0.1", ports[0], ProxyType.SOCKS5, country="Germany", country_code="DE", source="src")
    dead = Proxy("127.0.0.1", free_port(), ProxyType.SOCKS5, country_code="DE", source="src")
    ru_known = Proxy("127.0.0.3", ports[1], ProxyType.SOCKS5, country="Russia", country_code="RU", source="src")
    no_country = Proxy("127.0.0.2", ports[2], ProxyType.SOCKS5, source="src")  # 127.0.0.2 -> «РФ» по гео
    banned = Proxy("127.0.0.4", ports[3], ProxyType.SOCKS5, country_code="DE", source="src")
    proven = Proxy("127.0.0.5", ports[4], ProxyType.SOCKS5, source="старый")

    rep = Reputation.load(pathlib.Path(tempfile.mkdtemp()) / "rep.json")
    rep.update([CheckResult(banned, False, error="подменяет сертификат (1.1.1.1) — опасен")])
    rep.update([CheckResult(proven, True, latency_ms=10)])
    rep.update([CheckResult(proven, True, latency_ms=10)])
    rep.remember_countries({"127.0.0.5": ("DE", "Germany")})

    geo_calls = []

    def fake_lookup(ips):
        geo_calls.append(list(ips))
        known = {"127.0.0.2": geo.IpInfo("RU", "Russia", geo.NET_ISP, "AS1 Ru"),
                 "127.0.0.1": geo.IpInfo("DE", "Germany", geo.NET_ISP, "AS29518 Bredband2 AB"),
                 "127.0.0.5": geo.IpInfo("DE", "Germany", geo.NET_HOSTING, "AS24940 Hetzner Online GmbH")}
        return {ip: known[ip] for ip in ips if ip in known}

    stages = []
    results, st = await pipeline.run(
        [good, dead, ru_known, no_country, banned],
        rep,
        timeout=2,
        on_stage=lambda name, d, t: stages.append(name),
        lookup_ips=fake_lookup,
        check_kwargs={"probes": (checker.ProbeTarget("127.0.0.1", t_port, False),), "required_probes": ()},
        speed_kwargs={"target": quality.SpeedTarget("127.0.0.1", t_port, tls=False, path="/big")},
        prefilter_kwargs={"timeout": 1},
    )
    by = {(r.proxy.host, r.proxy.port): r for r in results}

    assert st.from_sources == 5 and st.from_reputation == 1, st
    assert st.skipped_by_reputation == 1 and (banned.host, banned.port) not in by
    print("OK: чёрный список не проверяется; «проверенный» из репутации добавлен к кандидатам")

    assert st.excluded_country == 2, st
    assert by[(ru_known.host, ru_known.port)].error == "прокси в России — исключён"
    assert by[(no_country.host, no_country.port)].error == "прокси в России — исключён"
    # спрашиваем только рабочих: у 127.0.0.2 нет страны, у остальных — типа сети
    assert len(geo_calls) == 1 and sorted(geo_calls[0]) == ["127.0.0.1", "127.0.0.2", "127.0.0.5"], geo_calls
    print("OK: РФ отсеяна и по данным источника, и по гео-поиску")

    assert st.prefilter_dead == 1 and by[(dead.host, dead.port)].error == checker.PREFILTER_DEAD_REASON
    print("OK: мёртвый порт отсеян быстрым отсевом, до полной проверки не дошёл")

    g, pr = by[(good.host, good.port)], by[(proven.host, proven.port)]
    assert g.working and pr.working and st.working == 2 and st.full_checked == 3  # 127.0.0.2 проверен, потом исключён по гео
    assert g.speed_kbps and pr.speed_kbps
    assert pr.rep_checks == 3 and pr.rep_ok == 3 and pr.proxy.country_code == "DE"
    assert rep.get(dead).fail_streak == 1 and rep.get(ru_known) is None
    print("OK: полная проверка + скорость; репутация обновлена (РФ туда не пишется)")
    assert stages[0] == "Быстрый отсев мёртвых" and stages.index("Проверка прокси") < stages.index("Определяю страны") < stages.index("Замер скорости")
    print("OK: этапы для прогресса:", " → ".join(dict.fromkeys(stages)))

    assert (g.proxy.network, g.proxy.asn) == (geo.NET_ISP, "AS29518 Bredband2 AB")
    assert pr.proxy.network == geo.NET_HOSTING and pr.proxy.country == "Germany"
    assert rep.network_of("127.0.0.1") == (geo.NET_ISP, "AS29518 Bredband2 AB")
    geo_calls.clear()
    good2 = Proxy("127.0.0.1", ports[0], ProxyType.SOCKS5, country_code="DE", source="src")
    results, _ = await pipeline.run(
        [good2], rep, timeout=2, lookup_ips=fake_lookup,
        check_kwargs={"probes": (checker.ProbeTarget("127.0.0.1", t_port, False),), "required_probes": ()},
        speed_kwargs={"target": quality.SpeedTarget("127.0.0.1", t_port, tls=False, path="/big")},
        prefilter_kwargs={"timeout": 1})
    again = next(r for r in results if r.proxy.port == ports[0] and r.proxy.host == "127.0.0.1")
    assert again.working and again.proxy.network == geo.NET_ISP
    assert geo_calls == [], geo_calls
    print("OK: тип сети (провайдер / хостинг) определяется у рабочих и берётся из кеша без повторного запроса")

    # «нет интернета»: ни один порт не открылся -> ошибка, репутация не портится
    rep2 = Reputation.load(pathlib.Path(tempfile.mkdtemp()) / "rep.json")
    try:
        await pipeline.run([Proxy("127.0.0.1", free_port(), ProxyType.SOCKS5, country_code="DE")], rep2,
                           lookup_ips=fake_lookup, prefilter_kwargs={"timeout": 0.5})
        raise AssertionError("ожидали ошибку")
    except RuntimeError as exc:
        assert "интернет" in str(exc)
    assert rep2.entries == {}
    print("OK: если не ответил вообще никто — ошибка «проверь интернет», репутация не портится")

    # «ферма»: много портов одного IP — проверяются не все; работавший раньше — всегда
    rep3 = Reputation.load(pathlib.Path(tempfile.mkdtemp()) / "rep.json")
    farm_good = Proxy("127.0.0.6", ports[0], ProxyType.SOCKS5, country_code="DE")
    farm_dead = [Proxy("127.0.0.6", free_port(), ProxyType.SOCKS5, country_code="DE") for _ in range(5)]
    old_good = Proxy("127.0.0.6", ports[1], ProxyType.SOCKS5, country_code="DE")
    rep3.update([CheckResult(old_good, True, latency_ms=10)])
    results, st = await pipeline.run(
        [farm_good] + farm_dead + [old_good], rep3, timeout=2, lookup_ips=fake_lookup,
        check_kwargs={"probes": (checker.ProbeTarget("127.0.0.1", t_port, False),), "required_probes": ()},
        speed_kwargs={"target": quality.SpeedTarget("127.0.0.1", t_port, tls=False, path="/big")},
        prefilter_kwargs={"timeout": 1})
    checked = {r.proxy.port for r in results}
    assert st.skipped_farms == 5 and len(results) == 2, (st, checked)
    assert checked == {farm_good.port, old_good.port}
    print("OK: лишние порты «фермы» не проверяются; работавший раньше прокси с того же IP — проверяется")

    for s in servers + [t_srv]:
        s.close()
    print("\nВсе тесты pipeline.py прошли.")


if __name__ == "__main__":
    asyncio.run(main())

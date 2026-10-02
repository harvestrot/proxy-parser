"""Офлайн-тесты сборщика: разбор API proxyscrape на сохранённом образце,
слияние дублей, поведение при недоступном/защищённом источнике."""
import json
import pathlib
import random
import sys
import time
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import scraper  # noqa: E402
from proxyparser.models import Proxy, ProxyType  # noqa: E402

FIX = pathlib.Path(__file__).parent / "fixtures"
PS = (FIX / "proxyscrape_sample.json").read_text(encoding="utf-8")


PS_ONLY = {"proxyscrape.com": scraper.scrape_proxyscrape}


def fake_fetch(url):
    if "api.proxyscrape.com" in url:
        return PS
    raise RuntimeError(f"неожиданный URL {url}")


def test_parse_proxyscrape():
    proxies = scraper.parse_proxyscrape(PS)
    addrs = {p.address: p for p in proxies}
    assert "1.2.3.4:1080" not in addrs, "мёртвый (alive=false) не должен попасть"
    assert "10.0.0.9:80" not in addrs, "HTTP без HTTPS/CONNECT (ssl=false) не нужен"
    assert addrs["45.155.71.236:1080"].type == ProxyType.SOCKS5
    assert addrs["83.56.15.57:5678"].type == ProxyType.SOCKS4
    assert addrs["46.47.197.210:3128"].type == ProxyType.HTTPS
    assert addrs["45.155.71.236:1080"].country == "Austria"
    assert all(p.source == "proxyscrape.com" for p in proxies)
    assert proxies[0].address == "46.47.197.210:3128", "сортировка по аптайму"
    assert len(scraper.parse_proxyscrape(PS, limit=1)) == 1
    print("OK: proxyscrape API — типы, фильтр мёртвых и HTTP без HTTPS, сортировка по аптайму, лимит")


def test_proxyscrape_url():
    q = parse_qs(urlsplit(scraper.proxyscrape_url("socks5")).query)
    assert q["protocol"] == ["socks5"] and q["format"] == ["json"] and q["timeout"] == ["3000"]
    print("OK: запрос к API proxyscrape формируется верно")


def test_merge_dedup():
    merged = scraper.merge([Proxy("1.1.1.1", 80, ProxyType.HTTPS), Proxy("1.1.1.1", 80, ProxyType.HTTPS),
                            Proxy("2.2.2.2", 80, ProxyType.SOCKS5)])
    assert len(merged) == 2
    print("OK: дубли схлопываются")


def test_scrape_direct_and_fallback():
    proxies, stats = scraper.scrape(fake_fetch, sources=PS_ONLY)
    assert stats.sources_ok == ["proxyscrape.com"], stats
    assert stats.per_source == {"proxyscrape.com": 3}
    assert stats.proxies_found == len(proxies) == 3
    print("OK: сбор со всех источников напрямую, дубли схлопнуты")

    def blocked(url):
        raise RuntimeError("timeout")

    proxies, stats = scraper.scrape(blocked, fallback_fetch=fake_fetch, sources=PS_ONLY)
    assert stats.sources_ok == ["proxyscrape.com"] and len(proxies) == 3
    print("OK: источники не открылись напрямую — взяты через прокси")

    proxies, stats = scraper.scrape(blocked, sources=PS_ONLY)
    assert set(stats.sources_failed) == {"proxyscrape.com"} and not proxies
    print("OK: без запасного пути ошибка источника фиксируется, программа не падает")


def test_bot_check_is_skipped_not_bypassed():
    challenge = '<html><head><title>Just a moment...</title><script>cf-chl</script></head></html>'
    assert scraper.looks_like_bot_check(503, challenge)
    assert not scraper.looks_like_bot_check(200, PS)
    calls = []

    def protected(url):
        raise scraper.SourceProtected("проверка на бота")

    def via_proxy(url):
        calls.append(url)
        return PS

    proxies, stats = scraper.scrape(protected, fallback_fetch=via_proxy, sources={"proxyscrape.com": scraper.scrape_proxyscrape})
    assert "proxyscrape.com" in stats.sources_failed and not calls
    print("OK: проверка на бота распознана, источник пропущен (без попыток обхода)")


def test_limit_farms():
    farm = [Proxy("45.74.31.%d" % (i % 10), 2000 + i, ProxyType.SOCKS5) for i in range(500)]
    block = [Proxy("193.176.84.%d" % i, 3128, ProxyType.HTTPS) for i in range(1, 25)]
    normal = [Proxy("8.8.%d.1" % i, 1080, ProxyType.SOCKS5) for i in range(20)]
    kept = scraper.limit_farms(farm + block + normal)
    farm_kept = [p for p in kept if p.host.startswith("45.74.31.")]
    assert len(farm_kept) == scraper.FARM_MAX_PER_SUBNET, len(farm_kept)
    assert max(sum(p.host == h for p in kept) for h in {p.host for p in farm_kept}) <= scraper.FARM_MAX_PER_IP
    assert sum(p.host.startswith("193.176.84.") for p in kept) == scraper.FARM_MAX_PER_SUBNET
    assert all(p in kept for p in normal), "обычные прокси из разных сетей не трогаются"
    assert kept == [p for p in farm + block + normal if p in kept], "порядок сохраняется"
    # уже работавшие раньше остаются, даже если подсеть переполнена
    vip = farm[-1]
    kept = scraper.limit_farms(farm, keep={(vip.host, vip.port)})
    assert vip in kept and len(kept) == scraper.FARM_MAX_PER_SUBNET
    print("OK: «фермы» урезаются (порты одного IP и адреса одной /24), остальные и проверенные не трогаются")


def test_plain_source_skips_farm_before_limit():
    text = "\n".join(f"45.74.31.{i % 10}:{3000 + i}" for i in range(3000))
    text += "\n" + "\n".join(f"9.{i}.1.1:1080" for i in range(40))
    collect = scraper.plain_source("s", "http://x", ProxyType.SOCKS5, limit=30, rng=random.Random(1))
    got = collect(lambda url: text)
    assert len(got) == 30
    assert sum(p.host.startswith("45.74.31.") for p in got) <= scraper.FARM_MAX_PER_SUBNET, got
    print("OK: лимит источника тратится на разные прокси, а не на порты одной фермы")


def _mirror(protocol, items):
    return json.dumps([{"protocol": protocol, "country": "Germany", "country_code": "DE", "ssl": True,
                        "anonymity": "elite", "last_checked": NOW - 600, **i} for i in items])


NOW = time.time()
MIRROR = {
    "socks5": _mirror("socks5", [
        {"ip": "45.155.71.236", "port": 1080, "uptime_percent": 60, "latency_ms": 900},
        {"ip": "5.6.7.8", "port": 1080, "uptime_percent": 95, "latency_ms": 5000},       # медленный по их замеру
        {"ip": "6.7.8.9", "port": 1080, "uptime_percent": 99, "latency_ms": 300, "last_checked": NOW - 86400},  # давно
        {"ip": "10.0.0.1", "port": 1080, "uptime_percent": 99, "latency_ms": 100},       # частный адрес
    ] + [{"ip": "45.74.31.1", "port": 4000 + i, "uptime_percent": 90, "latency_ms": 500} for i in range(50)]),
    "socks4": _mirror("socks4", [{"ip": "83.56.15.57", "port": 5678, "uptime_percent": 40, "latency_ms": 800}]),
    "http": _mirror("http", [
        {"ip": "46.47.197.210", "port": 3128, "uptime_percent": 95, "latency_ms": 300},
        {"ip": "7.7.7.7", "port": 80, "uptime_percent": 99, "latency_ms": 100, "ssl": False},  # без HTTPS
    ]),
}


def test_proxyscrape_github_mirror():
    got = scraper.parse_proxyscrape_github(MIRROR["socks5"], now=NOW)
    addrs = [p.address for p in got]
    assert "5.6.7.8:1080" not in addrs and "6.7.8.9:1080" not in addrs and "10.0.0.1:1080" not in addrs, addrs
    assert sum(a.startswith("45.74.31.1:") for a in addrs) == scraper.FARM_MAX_PER_IP
    assert addrs[0].startswith("45.74.31.1:") and "45.155.71.236:1080" in addrs, "сортировка по аптайму"
    assert got[-1].country_code == "DE" and got[-1].source == "proxyscrape.com"
    print("OK: зеркало proxyscrape на GitHub — фильтр по отклику, свежести, мусорным адресам и фермам")

    calls = []

    def api_down(url):
        calls.append(url)
        if "api.proxyscrape.com" in url:
            raise RuntimeError("Read timed out")  # Cloudflare из РФ: соединение «замирает»
        protocol = url.split("/protocols/")[1].split("/")[0]
        return MIRROR[protocol]

    proxies, stats = scraper.scrape(api_down, sources=PS_ONLY)
    assert sum("api.proxyscrape.com" in u for u in calls) == 1, "после первой неудачи API больше не ждём"
    assert {p.address for p in proxies} >= {"45.155.71.236:1080", "83.56.15.57:5678", "46.47.197.210:3128"}
    assert "7.7.7.7:80" not in {p.address for p in proxies}
    assert stats.sources_ok == ["proxyscrape.com"]
    print("OK: API proxyscrape не открылся — все типы взяты из зеркала на GitHub, таймаут API ждём один раз")


def test_merge_fills_country():
    a = Proxy("1.2.3.4", 1080, ProxyType.SOCKS5, source="без страны")
    b = Proxy("1.2.3.4", 1080, ProxyType.SOCKS5, country="Russia", country_code="RU", source="со страной")
    merged = scraper.merge([a, b])
    assert len(merged) == 1 and merged[0].source == "без страны" and merged[0].country_code == "RU"
    print("OK: при слиянии дублей страна берётся у того источника, где она есть")


if __name__ == "__main__":
    test_parse_proxyscrape()
    test_proxyscrape_url()
    test_merge_dedup()
    test_scrape_direct_and_fallback()
    test_bot_check_is_skipped_not_bypassed()
    test_limit_farms()
    test_plain_source_skips_farm_before_limit()
    test_proxyscrape_github_mirror()
    test_merge_fills_country()
    print("\nВсе тесты scraper.py прошли.")

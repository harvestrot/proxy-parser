"""Офлайн-тесты сборщика: разбор API proxyscrape на сохранённом образце,
слияние дублей, поведение при недоступном/защищённом источнике."""
import pathlib
import sys
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


if __name__ == "__main__":
    test_parse_proxyscrape()
    test_proxyscrape_url()
    test_merge_dedup()
    test_scrape_direct_and_fallback()
    test_bot_check_is_skipped_not_bypassed()
    print("\nВсе тесты scraper.py прошли.")

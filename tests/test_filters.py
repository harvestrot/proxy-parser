"""Исключение прокси из России: сразу «нерабочие», без сетевой проверки,
и выбрасываются из ранее сохранённых списков."""
import asyncio
import json
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import checker, scraper, storage  # noqa: E402
from proxyparser.filters import EXCLUDE_REASON, is_excluded  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402

PS = (pathlib.Path(__file__).parent / "fixtures" / "proxyscrape_sample.json").read_text(encoding="utf-8")


def main():
    assert is_excluded(Proxy("1.1.1.1", 1, ProxyType.SOCKS5, country_code="RU"))
    assert is_excluded(Proxy("1.1.1.1", 1, ProxyType.SOCKS5, country="Russia"))
    assert is_excluded(Proxy("1.1.1.1", 1, ProxyType.SOCKS5, country="Россия"))
    assert not is_excluded(Proxy("1.1.1.1", 1, ProxyType.SOCKS5, country="Belarus", country_code="BY"))
    assert not is_excluded(Proxy("1.1.1.1", 1, ProxyType.SOCKS5))
    print("OK: Россия распознаётся по коду и по названию страны, остальные — нет")

    ru = next(p for p in scraper.parse_proxyscrape(PS) if p.address == "46.47.197.210:3128")
    assert ru.country_code == "RU"
    print("OK: из API proxyscrape берётся код страны")

    # RU-прокси на «мёртвом» порту: если бы его проверяли по сети, был бы
    # таймаут/отказ; а должен сразу получить причину «исключён».
    t0 = time.monotonic()
    results = asyncio.run(checker.check_all([ru], timeout=5))
    assert results[0].working is False and results[0].error == EXCLUDE_REASON
    assert time.monotonic() - t0 < 0.5
    print("OK: прокси из России сразу помечен нерабочим, без сетевой проверки")

    tmp = pathlib.Path(tempfile.mkdtemp()) / "w.json"
    storage.save_results([
        CheckResult(Proxy("1.1.1.1", 1, ProxyType.SOCKS5, country="Russia"), True, 100),
        CheckResult(Proxy("2.2.2.2", 2, ProxyType.SOCKS5, country="Germany", country_code="DE"), True, 200),
    ], tmp)
    loaded = storage.load_working_proxies(tmp)
    assert [r.proxy.host for r in loaded] == ["2.2.2.2"]
    assert json.loads(tmp.read_text())["proxies"][1]["country_code"] == "DE"
    print("OK: из старого сохранённого списка российские прокси выбрасываются при загрузке")

    print("\nВсе тесты filters.py прошли.")


if __name__ == "__main__":
    main()

"""Файлы результатов переживают отключение света: запись атомарная, а
испорченный (обрезанный посреди записи) файл не роняет программу."""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import source_stats, storage  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402
from proxyparser.reputation import Reputation  # noqa: E402


def main():
    tmp = pathlib.Path(tempfile.mkdtemp())
    good = CheckResult(Proxy("8.8.8.8", 1080, ProxyType.SOCKS5, country="Германия", network="isp",
                             asn="AS29518 Bredband2 AB"), True, latency_ms=100, speed_kbps=900)

    path = tmp / "working.json"
    storage.save_results([good], path)
    loaded = storage.load_working_proxies(path)
    assert [r.proxy.address for r in loaded] == ["8.8.8.8:1080"]
    assert (loaded[0].proxy.network, loaded[0].proxy.asn) == ("isp", "AS29518 Bredband2 AB")  # для колонки «Сеть»
    assert not list(tmp.glob("*.tmp")), "временный файл должен исчезнуть после записи"
    print("OK: запись через временный файл, после неё на диске только целый файл")

    # обрыв посреди записи: обрезанный JSON (в том числе посреди русской буквы)
    raw = path.read_bytes()
    cut = raw.index("Германия".encode()) + 1  # середина двухбайтового символа
    for broken in (raw[: len(raw) // 2], raw[:cut], b""):
        path.write_bytes(broken)
        assert storage.load_working_proxies(path) == []
    print("OK: обрезанный список рабочих — пустой список, а не падение окна при запуске")

    rep_path = tmp / "rep.json"
    rep = Reputation(path=rep_path)
    rep.update([good])
    rep.remember_countries({"8.8.8.8": ("DE", "Германия")})
    rep.save()
    assert Reputation.load(rep_path).country_of("8.8.8.8") == ("DE", "Германия")
    data = rep_path.read_bytes()
    rep_path.write_bytes(data[: data.index("Германия".encode()) + 1])
    assert Reputation.load(rep_path).entries == {}
    rep_path.write_text("[1, 2]", encoding="utf-8")
    assert Reputation.load(rep_path).entries == {}
    print("OK: обрезанная репутация (и посреди символа, и не тот JSON) — чистая репутация, без падения")

    stats_path = tmp / "stats.json"
    stats_path.write_bytes(b'{"runs": [{"at": 1')
    totals = source_stats.save({"x": source_stats.SourceRow(listed=5)}, stats_path)
    assert totals["x"]["listed"] == 5 and json.loads(stats_path.read_text(encoding="utf-8"))["runs"]
    print("OK: обрезанная статистика источников — начинается заново, программа работает дальше")
    print("\nВсе тесты storage.py прошли.")


if __name__ == "__main__":
    main()

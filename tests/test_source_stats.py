"""Статистика источников: кто даёт рабочие/быстрые/уникальные прокси."""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import checker, filters, source_stats  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402


def R(addr, working, speed=None, udp=None, error=None, network=None):
    host, port = addr.split(":")
    return CheckResult(Proxy(host, int(port), ProxyType.SOCKS5, network=network), working, speed_kbps=speed,
                       udp_ms=udp, error=error)


def main():
    members = {
        "A": ["1.1.1.1:1", "2.2.2.2:2", "3.3.3.3:3", "4.4.4.4:4", "9.9.9.9:9"],
        "B": ["1.1.1.1:1", "5.5.5.5:5", "6.6.6.6:6"],
    }
    results = [
        R("1.1.1.1:1", True, speed=500, udp=50, network="isp"),        # есть в обоих
        R("2.2.2.2:2", True, speed=100, network="hosting"),            # только A
        R("3.3.3.3:3", False, error=checker.PREFILTER_DEAD_REASON),
        R("4.4.4.4:4", False, error=filters.EXCLUDE_REASON),
        R("5.5.5.5:5", True, speed=900, network="mobile"),             # только B
        R("6.6.6.6:6", False, error="timeout"),                        # живой порт, но не прошёл проверку
        # 9.9.9.9 не проверялся (чёрный список)
    ]
    rows = source_stats.compute(members, results)
    a, b = rows["A"], rows["B"]
    assert (a.listed, a.alive, a.working, a.fast, a.udp, a.unique_working) == (5, 2, 2, 1, 1, 1), a
    assert (b.listed, b.alive, b.working, b.fast, b.udp, b.unique_working) == (3, 3, 2, 2, 1, 1), b
    assert (a.isp, b.isp) == (1, 2), (a.isp, b.isp)
    print("OK: живые/рабочие/быстрые/UDP/у провайдера/уникальные считаются по каждому источнику")

    table = source_stats.format_table(rows)
    assert table[1].startswith("B"), table  # больше быстрых — выше
    print("OK: таблица отсортирована по числу быстрых:\n  " + "\n  ".join(table))

    path = pathlib.Path(tempfile.mkdtemp()) / "stats.json"
    source_stats.save(rows, path)
    totals = source_stats.save(rows, path)
    assert totals["B"]["runs"] == 2 and totals["B"]["fast"] == 4
    assert len(json.loads(path.read_text())["runs"]) == 2
    print("OK: итоги копятся между запусками")
    print("\nВсе тесты source_stats.py прошли.")


if __name__ == "__main__":
    main()

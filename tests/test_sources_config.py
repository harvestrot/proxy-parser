"""Источники из sources.json и универсальный разбор текстовых списков."""
import json
import pathlib
import random
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import scraper, sources_config  # noqa: E402
from proxyparser.models import ProxyType  # noqa: E402

LIST = """
# комментарий
1.1.1.1:1080
socks4://2.2.2.2:4145
http://3.3.3.3:8080   # хвост-комментарий
user:pass@4.4.4.4:1080
5.5.5.5:99999
not-a-proxy
socks5://6.6.6.6:1080
1.1.1.1:1080
"""


def main():
    found = scraper.parse_plain_list(LIST, ProxyType.SOCKS5, "x")
    by = {p.address: p.type for p in found}
    assert by == {"1.1.1.1:1080": ProxyType.SOCKS5, "2.2.2.2:4145": ProxyType.SOCKS4,
                  "3.3.3.3:8080": ProxyType.HTTPS, "6.6.6.6:1080": ProxyType.SOCKS5}, by
    assert len(scraper.parse_plain_list("1.1.1.1:80", None, "x")) == 0  # тип неизвестен и не задан
    print("OK: текстовые списки: ip:port, схемы socks5/socks4/http, комментарии, мусор, логины пропускаются")

    extra = scraper.parse_plain_list(
        "8.8.4.4:1080:United States\n"      # hideip.me — страна после порта
        "9.9.9.9:4145 US-N-S +\n"           # spys.me — хвост игнорируется
        "7.7.7.7:1080:user:pass\n"          # с авторизацией — не нужен
        "0.0.0.0:80\n127.0.0.1:1080\n10.1.2.3:1080\n192.168.0.1:1080\n"  # служебные / частные
        "300.1.1.1:1080\n",
        ProxyType.SOCKS5, "x")
    by = {p.address: p for p in extra}
    assert set(by) == {"8.8.4.4:1080", "9.9.9.9:4145"}, set(by)
    assert by["8.8.4.4:1080"].country == "United States" and by["9.9.9.9:4145"].country is None
    print("OK: форматы «ip:port:Страна» и «ip:port хвост»; частные и служебные адреса отброшены")

    collect = scraper.plain_source("s", "http://x", ProxyType.SOCKS5, limit=2, rng=random.Random(0))
    sample = collect(lambda url: LIST)
    assert len(sample) == 2
    print("OK: лимит — случайная выборка, дубли внутри списка схлопнуты")

    tmp = pathlib.Path(tempfile.mkdtemp()) / "sources.json"
    sources = sources_config.load_sources(tmp)
    assert tmp.exists(), "файл должен создаться с настройками по умолчанию"
    cfg = json.loads(tmp.read_text(encoding="utf-8"))
    enabled = [s["name"] for s in cfg["sources"] if s.get("enabled")]
    assert list(sources) == enabled and "proxyscrape.com" in sources
    print(f"OK: sources.json создан по умолчанию, включены: {', '.join(enabled)}")

    tmp.write_text(json.dumps({"sources": [
        {"name": "A", "kind": "plain", "url": "http://a", "type": "socks5"},
        {"name": "B", "kind": "plain", "type": "socks5"},                 # нет url — с ошибкой
        {"name": "C", "kind": "weird", "url": "http://c"},                # неизвестный kind
        {"name": "D", "kind": "plain", "url": "http://d", "type": "vpn"},  # неизвестный тип
        {"name": "E", "kind": "proxyscrape", "enabled": False},
        {"name": "F", "kind": "proxyscrape"},
    ]}), encoding="utf-8")
    sources = sources_config.load_sources(tmp)
    assert list(sources) == ["A", "F"], list(sources)
    print("OK: ошибочные и выключенные записи пропускаются, остальные работают")

    # Блокнот: «UTF-8 с BOM» и ANSI (cp1251) с русскими буквами в названии
    notepad = {"sources": [{"name": "мой список", "kind": "plain", "url": "http://a", "type": "socks5"}]}
    text = json.dumps(notepad, ensure_ascii=False)
    for encoded in (b"\xef\xbb\xbf" + text.encode("utf-8"), text.encode("cp1251")):
        tmp.write_bytes(encoded)
        assert list(sources_config.load_sources(tmp)) == ["мой список"]
    tmp.write_text('[{"name": "x"}]', encoding="utf-8")  # не тот формат — встроенные, без падения
    assert list(sources_config.load_sources(tmp)) == list(scraper.SOURCES)
    print("OK: sources.json из Блокнота (UTF-8 с BOM, ANSI) читается; файл не того формата не роняет обновление")

    tmp.write_text("{ сломанный json", encoding="utf-8")
    assert list(sources_config.load_sources(tmp)) == list(scraper.SOURCES)
    print("OK: повреждённый sources.json -> встроенные источники (файл пользователя не перезаписывается)")
    assert tmp.read_text(encoding="utf-8") == "{ сломанный json"

    print("\nВсе тесты sources_config.py прошли.")


if __name__ == "__main__":
    main()

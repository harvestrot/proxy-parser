"""Страна и тип сети по IP: разбор ответа ip-api и множители для выбора прокси."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import geo  # noqa: E402


def main():
    calls = []

    def fake_post(url, payload):
        calls.append((url, list(payload)))
        return [
            {"status": "success", "query": "85.8.47.207", "countryCode": "SE", "country": "Sweden",
             "hosting": False, "mobile": False, "as": "AS29518 Bredband2 AB"},
            {"status": "success", "query": "5.75.133.113", "countryCode": "DE", "country": "Germany",
             "hosting": True, "mobile": False, "as": "AS24940 Hetzner Online GmbH"},
            {"status": "success", "query": "31.173.1.1", "countryCode": "FI", "country": "Finland",
             "hosting": False, "mobile": True, "as": "AS719 Elisa Oyj"},
            {"status": "success", "query": "1.2.3.4", "countryCode": "US", "country": "United States"},
            {"status": "fail", "query": "9.9.9.9", "message": "reserved range"},
        ]

    ips = ["85.8.47.207", "5.75.133.113", "31.173.1.1", "1.2.3.4", "9.9.9.9", "85.8.47.207"]
    got = geo.lookup_ips(ips, post=fake_post)
    assert len(calls) == 1 and calls[0][1] == ips[:5]  # дубли не спрашиваем
    assert "hosting" in calls[0][0] and "mobile" in calls[0][0] and "as" in calls[0][0]
    assert got["85.8.47.207"] == geo.IpInfo("SE", "Sweden", geo.NET_ISP, "AS29518 Bredband2 AB")
    assert got["5.75.133.113"].network == geo.NET_HOSTING
    assert got["31.173.1.1"].network == geo.NET_MOBILE  # мобильная важнее флага хостинга
    assert got["1.2.3.4"].network is None and got["1.2.3.4"].country_code == "US"  # полей о сети нет — неизвестно
    assert "9.9.9.9" not in got
    print("OK: тип сети: провайдер / хостинг / мобильная / неизвестно — из того же запроса, что и страна")

    def broken_post(url, payload):
        raise OSError("нет сети")

    assert geo.lookup_ips(["1.1.1.1"], post=broken_post) == {}
    print("OK: гео-API недоступен — пустой ответ, а не падение")

    assert geo.network_factor(geo.NET_ISP) > geo.network_factor(None) > geo.network_factor(geo.NET_HOSTING)
    assert geo.network_factor(geo.NET_MOBILE) == geo.network_factor(geo.NET_ISP)
    print("OK: множитель сети: провайдер/мобильная > неизвестно > хостинг")
    print("\nВсе тесты geo.py прошли.")


if __name__ == "__main__":
    main()

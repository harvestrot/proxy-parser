import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402
from proxyparser.singbox_config import build_config, pick_proxies  # noqa: E402


def r(host, ptype, latency, working=True):
    return CheckResult(proxy=Proxy(host, 1080, ptype), working=working, latency_ms=latency)


def test_socks5_only_when_enough_fast():
    results = [
        r("1.0.0.1", ProxyType.SOCKS5, 400), r("1.0.0.2", ProxyType.SOCKS5, 900),
        r("1.0.0.3", ProxyType.SOCKS5, 1500), r("1.0.0.4", ProxyType.SOCKS5, 9000),  # медленный — не берём
        r("2.0.0.1", ProxyType.SOCKS4, 100), r("3.0.0.1", ProxyType.HTTPS, 50),
        r("1.0.0.9", ProxyType.SOCKS5, None, working=False),
    ]
    chosen, used = pick_proxies(results)
    assert used == [ProxyType.SOCKS5], used
    assert [c.proxy.host for c in chosen] == ["1.0.0.1", "1.0.0.2", "1.0.0.3"]
    print("OK: хватает быстрых SOCKS5 — берём только их, медленные отброшены")


def test_fills_up_from_next_tiers():
    results = [r("1.0.0.1", ProxyType.SOCKS5, 700), r("3.0.0.1", ProxyType.HTTPS, 300), r("3.0.0.2", ProxyType.HTTPS, 600)]
    chosen, used = pick_proxies(results)
    assert used == [ProxyType.SOCKS5, ProxyType.HTTPS], used
    assert chosen[0].proxy.type == ProxyType.SOCKS5 and len(chosen) == 3
    config, meta = build_config(results)
    types = sorted(o["type"] for o in config["outbounds"] if o["type"] in ("socks", "http"))
    assert types == ["http", "http", "socks"], types
    print("OK: мало SOCKS5 — добираем следующими типами:", meta["comment_ru"])


def test_only_slow_available():
    chosen, used = pick_proxies([r("3.0.0.1", ProxyType.HTTPS, 5000), r("1.0.0.1", ProxyType.SOCKS5, 7000)])
    assert used == [ProxyType.SOCKS5] and len(chosen) == 1
    print("OK: быстрых нет — берём лучшие по приоритету")


def test_config_shape():
    config, _ = build_config([r("1.0.0.1", ProxyType.SOCKS5, 400), r("2.0.0.1", ProxyType.SOCKS4, 500)])
    json.dumps(config)
    socks4 = [o for o in config["outbounds"] if o.get("version") == "4a"]
    assert len(socks4) == 1
    urltest = next(o for o in config["outbounds"] if o["type"] == "urltest")
    assert urltest["interval"] == "30s" and len(urltest["outbounds"]) == 2
    assert config["route"]["final"] == "auto"
    assert config["dns"]["servers"][0]["type"] == "https"
    assert config["experimental"]["clash_api"]["external_controller"] == "127.0.0.1:9090"
    actions = [rule.get("action") for rule in config["route"]["rules"]]
    assert "hijack-dns" in actions and "sniff" in actions
    print("OK: структура конфига")


def test_speed_ranking_and_slow_drop():
    results = [
        CheckResult(Proxy("1.0.0.1", 1080, ProxyType.SOCKS5), True, latency_ms=300, speed_kbps=60),
        CheckResult(Proxy("1.0.0.2", 1080, ProxyType.SOCKS5), True, latency_ms=900, speed_kbps=800),
        CheckResult(Proxy("1.0.0.3", 1080, ProxyType.SOCKS5), True, latency_ms=500, speed_kbps=None),
        CheckResult(Proxy("1.0.0.4", 1080, ProxyType.SOCKS5), True, latency_ms=200, speed_kbps=10),  # медленный
        CheckResult(Proxy("1.0.0.5", 1080, ProxyType.SOCKS5), True, latency_ms=700, speed_kbps=200),
    ]
    chosen, _ = pick_proxies(results)
    hosts = [c.proxy.host for c in chosen]
    assert hosts[:2] == ["1.0.0.2", "1.0.0.5"], hosts  # сначала быстрые по реальной скорости
    assert "1.0.0.4" not in hosts, "медленный по замеру выброшен"
    print("OK: прокси с хорошей реальной скоростью идут первыми, совсем медленные отброшены")


def test_group_only_speed_proven_when_enough():
    results = [
        CheckResult(Proxy("2.0.0.1", 1080, ProxyType.SOCKS5), True, latency_ms=400, speed_kbps=90),    # низкий пинг, но медленный
        CheckResult(Proxy("2.0.0.2", 1080, ProxyType.SOCKS5), True, latency_ms=450, speed_kbps=5000),
        CheckResult(Proxy("2.0.0.3", 1080, ProxyType.SOCKS5), True, latency_ms=700, speed_kbps=800),
        CheckResult(Proxy("2.0.0.4", 1080, ProxyType.SOCKS5), True, latency_ms=1200, speed_kbps=600),
        CheckResult(Proxy("2.0.0.5", 1080, ProxyType.SOCKS5), True, latency_ms=300, speed_kbps=None),  # не замерен
    ]
    chosen, _ = pick_proxies(results)
    assert [c.proxy.host for c in chosen] == ["2.0.0.2", "2.0.0.3", "2.0.0.4"], [c.proxy.host for c in chosen]
    print("OK: хватает прокси с доказанной скоростью — в группе только они (sing-box не выберет «быстрый по пингу, но медленный»)")


def test_discord_voice_direct():
    base = [r("1.0.0.1", ProxyType.SOCKS5, 400), r("1.0.0.2", ProxyType.SOCKS5, 500), r("1.0.0.3", ProxyType.SOCKS5, 600)]
    config, meta = build_config(base)
    rules = config["route"]["rules"]
    discord = [x for x in rules if "process_name" in x]
    assert discord and discord[0]["outbound"] == "direct" and discord[0]["network"] == "udp"
    assert "Discord.exe" in discord[0]["process_name"]
    assert {"network": "udp", "port": 443, "action": "reject"} in rules  # QUIC — сразу отказ
    assert not any(o["tag"] == "auto-udp" for o in config["outbounds"])
    assert all(o.get("connect_timeout") == "5s" for o in config["outbounds"] if o["type"] in ("socks", "http"))
    assert "Голос Discord — напрямую" in meta["comment_ru"]
    print("OK: UDP через бесплатные прокси не идёт — голос Discord напрямую, QUIC отклоняется; таймаут подключения 5 с")


def test_reliability_and_geo_in_ranking():
    def res(host, speed, ok, checks, cc):
        return CheckResult(Proxy(host, 1080, ProxyType.SOCKS5, country_code=cc), True, latency_ms=500,
                           speed_kbps=speed, rep_ok=ok, rep_checks=checks)
    results = [
        res("3.0.0.1", 1000, 0, 0, "BR"),   # быстрый, но новичок и далеко
        res("3.0.0.2", 800, 9, 10, "DE"),   # чуть медленнее, но надёжный и рядом
        res("3.0.0.3", 900, 1, 10, "US"),   # часто падает
    ]
    chosen, _ = pick_proxies(results)
    assert [c.proxy.host for c in chosen][0] == "3.0.0.2", [c.proxy.host for c in chosen]
    print("OK: при близкой скорости первым идёт надёжный и географически близкий прокси")


def test_isp_network_ahead_of_hosting():
    def res(host, speed, network):
        return CheckResult(Proxy(host, 1080, ProxyType.HTTPS, country_code="SE", network=network), True,
                           latency_ms=130, speed_kbps=speed)
    results = [
        res("4.0.0.1", 2900, "hosting"),  # чуть быстрее по замеру, но хостинг (его ТСПУ может придушить)
        res("4.0.1.1", 2700, "isp"),      # сеть обычного провайдера
        res("4.0.2.1", 2700, None),       # тип сети неизвестен
        res("4.0.3.1", 6000, "hosting"),  # намного быстрее — хостинг не мешает быть первым
    ]
    chosen, _ = pick_proxies(results)
    hosts = [c.proxy.host for c in chosen]
    assert hosts == ["4.0.3.1", "4.0.1.1", "4.0.2.1", "4.0.0.1"], hosts
    print("OK: при близкой скорости сеть провайдера впереди хостинга; намного более быстрый хостинг — первый")


def test_ranked_for_table():
    from proxyparser.singbox_config import ranked

    def res(host, speed, ok=0, checks=0, working=True):
        return CheckResult(Proxy(host, 1080, ProxyType.SOCKS5), working, latency_ms=300, speed_kbps=speed,
                           rep_ok=ok, rep_checks=checks)
    results = [res("5.0.0.1", 900), res("5.0.1.1", 60), res("5.0.2.1", 7000, ok=1, checks=5),
               res("5.0.3.1", 4000), res("5.0.4.1", 9000, working=False)]
    assert [r.proxy.host for r in ranked(results)] == ["5.0.3.1", "5.0.0.1", "5.0.2.1", "5.0.1.1"]
    print("OK: таблица — по рейтингу VPN: быстрые сверху, нестабильные и медленные — внизу, нерабочих нет")


def test_nodes_in_vpn():
    from proxyparser import app_routing as ar, nodes
    uuid = "11111111-2222-3333-4444-555555555555"
    links = [f"vless://{uuid}@a.3dns.vip:443?security=tls&type=ws&path=%2F",
             f"vless://{uuid}@b.3dns.vip:443?security=tls&type=ws&path=%2F",
             f"vless://{uuid}@c.3dns.vip:443?security=tls&type=ws&path=%2F",   # третий того же провайдера
             f"vless://{uuid}@7.7.7.7:443?security=reality&sni=x.com&pbk=key&sid=ab",
             "trojan://pw@tr.example.org:443?sni=tr.example.org"]
    node_results = [CheckResult(nodes.parse_link(link), True, latency_ms=300 + i, speed_kbps=3000 - i * 100)
                    for i, link in enumerate(links)]
    plain = [CheckResult(Proxy("2.2.2.2", 1080, ProxyType.SOCKS5), True, latency_ms=200, speed_kbps=900)]
    cfg, meta = build_config(node_results + plain)
    obs = {o["tag"]: o for o in cfg["outbounds"]}
    vless = [o for o in obs.values() if o["type"] == "vless"]
    assert vless and all(o["uuid"] == uuid and o["connect_timeout"] == "5s" for o in vless)
    by_server = {o["server"]: o for o in obs.values() if "server" in o}
    assert by_server["a.3dns.vip"]["domain_resolver"] == {"server": "direct-dns", "strategy": "ipv4_only"}
    assert "domain_resolver" not in by_server["7.7.7.7"]  # у IP искать нечего
    assert "c.3dns.vip" not in by_server, "не больше 2 узлов одного провайдера (*.3dns.vip)"
    assert [s["tag"] for s in cfg["dns"]["servers"]] == ["remote-dns", "direct-dns"]
    assert cfg["route"]["default_domain_resolver"] == "remote-dns"
    print("OK: узлы — outbound VLESS/Trojan из ссылок; адрес узла-домена — прямым DoH; "
          "не больше 2 узлов одного провайдера")

    udp = obs["auto-udp"]
    assert udp["type"] == "urltest" and set(udp["outbounds"]) <= set(obs)
    assert {obs[t]["type"] for t in udp["outbounds"]} <= {"vless", "trojan"}, "в UDP-группе только узлы"
    rules = cfg["route"]["rules"]
    assert {"network": "udp", "outbound": "auto-udp"} in rules
    assert not any(r.get("process_name") == DISCORD and r.get("outbound") == "direct" for r in rules)
    assert meta["udp_count"] == len(udp["outbounds"]) and "UDP (звонки, игры) — через" in meta["comment_ru"]
    print(f"OK: есть узлы — UDP (голос Discord, игры) через группу из {meta['udp_count']} узлов, QUIC по-прежнему отклоняется")

    apps = [ar.app_for_exe("Discord.exe")]
    cfg, _ = build_config(node_results, routing=ar.RoutingSettings(ar.MODE_ONLY, apps))
    names = ["Discord.exe", "discord.exe"]
    assert {"process_name": names, "network": "udp", "outbound": "auto-udp"} in cfg["route"]["rules"]
    assert [s["tag"] for s in cfg["dns"]["servers"]] == ["direct-dns"]
    print("OK: «только выбранные» — их UDP тоже через узлы")


DISCORD = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"]


def test_bypass_rule_for_own_process():
    config, _ = build_config([r("1.0.0.1", ProxyType.SOCKS5, 400)], bypass_process_paths=[r"C:\\Py\\pythonw.exe", r"C:\\Py\\pythonw.exe"])
    rules = config["route"]["rules"]
    bypass = [x for x in rules if "process_path" in x]
    assert bypass == [{"process_path": [r"C:\\Py\\pythonw.exe"], "outbound": "direct"}], bypass
    assert rules.index(bypass[0]) < next(i for i, x in enumerate(rules) if x.get("action") == "reject")
    config2, _ = build_config([r("1.0.0.1", ProxyType.SOCKS5, 400)])
    assert not any("process_path" in x for x in config2["route"]["rules"])
    print("OK: трафик самой программы идёт мимо VPN (правило process_path)")


def test_subnet_diversity():
    from proxyparser.singbox_config import diversify, subnet
    farm = [CheckResult(Proxy(f"45.74.31.{20 + i}", 4000 + i, ProxyType.SOCKS5), True, latency_ms=300, speed_kbps=900 - i)
            for i in range(6)]
    others = [CheckResult(Proxy("160.187.0.89", 1080, ProxyType.SOCKS5), True, latency_ms=900, speed_kbps=760),
              CheckResult(Proxy("5.75.133.113", 10812, ProxyType.SOCKS5), True, latency_ms=900, speed_kbps=700)]
    chosen, _ = pick_proxies(farm + others)
    nets = [subnet(c.proxy.host) for c in chosen]
    assert nets.count("45.74.31") == 2 and "160.187.0" in nets and "5.75.133" in nets, nets
    print("OK: из одной «фермы» /24 в группу берутся максимум 2 прокси, остальные места — другим операторам")
    only_farm = diversify(farm[:4])
    assert len(only_farm) == 3  # меньше MIN_PROXIES не опускаемся
    print("OK: если кроме фермы ничего нет — группа всё равно набирается")


def test_latency_matters_and_fast_https_not_lost():
    S5, H = ProxyType.SOCKS5, ProxyType.HTTPS
    results = [
        CheckResult(Proxy("4.0.0.1", 1080, S5), True, latency_ms=6000, speed_kbps=900),   # быстрый, но отклик 6 с
        CheckResult(Proxy("4.0.1.1", 1080, S5), True, latency_ms=1100, speed_kbps=1100),
        CheckResult(Proxy("4.0.2.1", 1080, S5), True, latency_ms=1200, speed_kbps=1000),
        CheckResult(Proxy("4.0.3.1", 8080, H), True, latency_ms=400, speed_kbps=1800),     # лучший — HTTPS
        CheckResult(Proxy("4.0.4.1", 1080, S5), True, latency_ms=300, speed_kbps=None),
        CheckResult(Proxy("4.0.5.1", 1080, S5), True, latency_ms=7000, speed_kbps=50),
        CheckResult(Proxy("4.0.6.1", 1080, S5), True, latency_ms=900, speed_kbps=50),
    ]
    chosen, used = pick_proxies(results)
    hosts = [c.proxy.host for c in chosen]
    assert "4.0.0.1" not in hosts, "отклик 6 с — в группу не берём, какая бы ни была скорость"
    assert set(hosts) == {"4.0.1.1", "4.0.2.1", "4.0.3.1"} and used == [S5, H], (hosts, used)
    print("OK: прокси с откликом в секунды не попадают в группу; быстрый HTTPS не теряется из-за типа")


def test_few_good_filled_only_to_minimum():
    results = [CheckResult(Proxy("5.0.0.1", 1080, ProxyType.SOCKS5), True, latency_ms=800, speed_kbps=900)] + [
        CheckResult(Proxy(f"5.0.{i}.1", 1080, ProxyType.SOCKS5), True, latency_ms=300 + i, speed_kbps=None)
        for i in range(1, 10)]
    chosen, _ = pick_proxies(results)
    assert len(chosen) == 3 and chosen[0].proxy.host == "5.0.0.1", [c.proxy.host for c in chosen]
    print("OK: быстрых меньше трёх — добираем только до трёх, а не размываем группу непроверенными")


def test_slow_never_fill_the_group():
    S5 = ProxyType.SOCKS5
    results = [
        CheckResult(Proxy("6.0.0.1", 1080, S5), True, latency_ms=600, speed_kbps=1200),
        CheckResult(Proxy("6.0.1.1", 1080, S5), True, latency_ms=150, speed_kbps=90),   # медленный, хоть и быстрый пинг
        CheckResult(Proxy("6.0.2.1", 1080, S5), True, latency_ms=200, speed_kbps=0),    # данные не пошли
        CheckResult(Proxy("6.0.3.1", 1080, S5), True, latency_ms=900, speed_kbps=250),  # приемлемый
        CheckResult(Proxy("6.0.4.1", 1080, S5), True, latency_ms=700, speed_kbps=None), # не замерен
    ]
    chosen, _ = pick_proxies(results)
    hosts = [c.proxy.host for c in chosen]
    assert hosts == ["6.0.0.1", "6.0.3.1", "6.0.4.1"], hosts
    print("OK: хороших мало — добираем приемлемыми и незамеренными, но НЕ медленными по замеру")

    only_fair = [CheckResult(Proxy(f"6.1.{i}.1", 1080, S5), True, latency_ms=500, speed_kbps=200 + i) for i in range(5)]
    chosen, _ = pick_proxies(only_fair + results[1:3])
    assert len(chosen) == 5 and all(c.speed_kbps >= 150 for c in chosen)
    print("OK: «хороших» (от 500 КБ/с) нет — группа из приемлемых (от 150 КБ/с)")

    all_slow = [CheckResult(Proxy(f"6.2.{i}.1", 1080, S5), True, latency_ms=500, speed_kbps=30 + i) for i in range(4)]
    chosen, _ = pick_proxies(all_slow)
    assert chosen, "совсем без прокси VPN не запустится — медленные только как крайний случай"
    _, meta = build_config(all_slow)
    assert "ВНИМАНИЕ" in meta["comment_ru"], meta["comment_ru"]
    print("OK: быстрых нет вовсе — берём медленные, но честно предупреждаем в журнале")


def test_unstable_go_last():
    S5 = ProxyType.SOCKS5

    def res(host, speed, ok, checks):
        return CheckResult(Proxy(host, 1080, S5), True, latency_ms=500, speed_kbps=speed, rep_ok=ok, rep_checks=checks)
    results = [
        res("7.0.0.1", 3000, 1, 8),   # самый быстрый, но по истории чаще падал
        res("7.0.1.1", 900, 6, 7), res("7.0.2.1", 800, 0, 0), res("7.0.3.1", 700, 3, 3),
    ]
    chosen, _ = pick_proxies(results)
    assert "7.0.0.1" not in [c.proxy.host for c in chosen], [c.proxy.host for c in chosen]
    chosen, _ = pick_proxies(results[:2])
    assert [c.proxy.host for c in chosen] == ["7.0.1.1", "7.0.0.1"]
    print("OK: нестабильные по истории не берутся, пока хватает стабильных (только добором)")

    # случай из лога: при подключении sing-box ушёл на «быстрый по пингу»
    # прокси, прошедший лишь 4 проверки из 8, и первую минуту всё тормозило
    log_case = [
        CheckResult(Proxy("185.87.255.47", 1080, S5), True, latency_ms=243, speed_kbps=3567, rep_ok=7, rep_checks=8),
        CheckResult(Proxy("89.208.107.165", 1080, S5), True, latency_ms=298, speed_kbps=2906, rep_ok=2, rep_checks=2),
        CheckResult(Proxy("135.136.188.213", 1081, S5), True, latency_ms=580, speed_kbps=1840, rep_ok=4, rep_checks=8),
        CheckResult(Proxy("160.187.0.89", 1080, S5), True, latency_ms=700, speed_kbps=900, rep_ok=5, rep_checks=6),
    ]
    config, _ = build_config(log_case)
    auto = next(o for o in config["outbounds"] if o["tag"] == "auto")
    hosts = [t.split("-")[2].replace("_", ".") for t in auto["outbounds"]]
    assert hosts == ["185.87.255.47", "89.208.107.165", "160.187.0.89"], hosts
    assert auto["tolerance"] >= 1000
    print("OK: прокси, прошедший 4 проверки из 8, в группу не попал; лучшие по рейтингу — первыми, "
          "а большой допуск urltest не даёт sing-box уйти с них из-за случайно меньшего пинга")


def test_app_routing_modes():
    from proxyparser import app_routing as ar
    results = [r("1.0.0.1", ProxyType.SOCKS5, 400), r("1.0.0.2", ProxyType.SOCKS5, 500),
               r("1.0.0.3", ProxyType.SOCKS5, 600)]
    apps = [ar.app_for_exe("chrome.exe"), ar.app_for_exe("Discord.exe")]

    def rules_of(cfg):
        return [x for x in cfg["route"]["rules"] if x.get("action") not in ("sniff", "hijack-dns")
                and "process_path" not in x and not x.get("ip_is_private")]

    cfg, meta = build_config(results)
    assert cfg["route"]["final"] == "auto" and cfg["dns"]["servers"][0]["detour"] == "auto"
    assert not any("process_name" in x and x.get("outbound") == "auto" for x in cfg["route"]["rules"])
    print("OK: по умолчанию — весь трафик через прокси, как раньше")

    cfg, meta = build_config(results, routing=ar.RoutingSettings(ar.MODE_ONLY, apps))
    names = ["chrome.exe", "Discord.exe", "discord.exe"]
    assert cfg["route"]["final"] == "direct"
    assert rules_of(cfg) == [
        {"process_name": names, "network": "udp", "port": 443, "action": "reject"},
        {"process_name": names, "network": "tcp", "outbound": "auto"},
    ], rules_of(cfg)
    assert cfg["dns"]["final"] == "direct-dns" and "detour" not in cfg["dns"]["servers"][0]
    assert "Через прокси: Google Chrome, Discord" in meta["comment_ru"]
    print("OK: «только выбранные» — их трафик через прокси, остальное и DNS напрямую "
          "(умрут прокси — остальной интернет работает)")

    cfg, _ = build_config(results, routing=ar.RoutingSettings(ar.MODE_ONLY, []))
    assert cfg["route"]["final"] == "direct" and rules_of(cfg) == []
    print("OK: «только выбранные» без приложений — всё напрямую")

    cfg, meta = build_config(results, routing=ar.RoutingSettings(ar.MODE_EXCEPT, apps))
    rules = rules_of(cfg)
    assert cfg["route"]["final"] == "auto"
    assert rules[0] == {"process_name": names, "outbound": "direct"}, rules  # раньше отказа QUIC — им QUIC можно
    assert {"network": "udp", "port": 443, "action": "reject"} in rules[1:]
    assert "Мимо прокси: Google Chrome, Discord" in meta["comment_ru"]
    print("OK: «всё, кроме выбранных» — выбранные напрямую (и с QUIC), остальное через прокси")


def test_pinned_and_countries():
    from proxyparser import app_routing as ar

    def res(host, cc, speed, latency=500, working=True):
        return CheckResult(Proxy(host, 1080, ProxyType.SOCKS5, country_code=cc), working,
                           latency_ms=latency, speed_kbps=speed)
    results = [res("9.0.0.1", "DE", 3000), res("9.0.1.1", "NL", 2500), res("9.0.2.1", "US", 2000),
               res("9.0.3.1", "SE", 160, latency=2400)]  # медленный — в группу сам не попал бы

    cfg, meta = build_config(results, pinned="9.0.1.1:1080")
    sel = next(o for o in cfg["outbounds"] if o["type"] == "selector")
    pin_tag = sel["outbounds"][0]
    assert sel["tag"] == "pinned" and sel["outbounds"] == [pin_tag, "auto"] and sel["default"] == pin_tag
    assert "9_0_1_1" in pin_tag and cfg["route"]["final"] == "pinned" and cfg["dns"]["servers"][0]["detour"] == "pinned"
    assert meta["pin_tag"] == pin_tag and "Закреплён прокси 9.0.1.1:1080" in meta["comment_ru"]
    print("OK: закреплённый прокси — через переключатель «закреплённый / автовыбор», DNS тоже через него")

    cfg, meta = build_config(results, pinned="9.0.3.1:1080")
    auto = next(o for o in cfg["outbounds"] if o["tag"] == "auto")
    assert meta["pin_tag"] in auto["outbounds"], "закреплённый должен проверяться sing-box (быть в группе)"
    print("OK: закреплённый, не попавший в группу по скорости, всё равно добавлен — sing-box следит, жив ли он")

    cfg, meta = build_config(results, pinned="1.2.3.4:1")
    assert cfg["route"]["final"] == "auto" and not any(o["type"] == "selector" for o in cfg["outbounds"])
    assert meta["pin_tag"] is None and "сейчас не работает" in meta["comment_ru"]
    print("OK: закреплённого нет среди рабочих — честный автовыбор с пометкой в журнале")

    cfg, _ = build_config(results, pinned="9.0.0.1:1080",
                          routing=ar.RoutingSettings(ar.MODE_ONLY, [ar.app_for_exe("chrome.exe")]))
    assert {"process_name": ["chrome.exe"], "network": "tcp", "outbound": "pinned"} in cfg["route"]["rules"]
    print("OK: «только выбранные приложения» + закреплённый — их трафик идёт через него")

    cfg, meta = build_config(results, countries=["DE", "NL"])
    hosts = {o.get("server") for o in cfg["outbounds"] if o["type"] == "socks"}
    assert hosts == {"9.0.0.1", "9.0.1.1"}, hosts
    assert "Страны: DE, NL" in meta["comment_ru"]
    cfg, meta = build_config(results, countries=["JP"])
    assert len([o for o in cfg["outbounds"] if o["type"] == "socks"]) >= 3 and "ВНИМАНИЕ" in meta["comment_ru"]
    cfg, _ = build_config(results, countries=["DE"], pinned="9.0.2.1:1080")
    assert any(o.get("server") == "9.0.2.1" for o in cfg["outbounds"]), "закреплённому фильтр стран не мешает"
    print("OK: фильтр стран; в выбранных странах никого — берём любые и предупреждаем; закреплённый — вне фильтра")


def test_no_working_raises():
    try:
        build_config([r("1.1.1.1", ProxyType.SOCKS5, None, working=False)])
    except ValueError:
        print("OK: нет рабочих — ошибка")
        return
    raise AssertionError("ожидали ValueError")


if __name__ == "__main__":
    test_socks5_only_when_enough_fast()
    test_fills_up_from_next_tiers()
    test_only_slow_available()
    test_config_shape()
    test_speed_ranking_and_slow_drop()
    test_group_only_speed_proven_when_enough()
    test_discord_voice_direct()
    test_reliability_and_geo_in_ranking()
    test_isp_network_ahead_of_hosting()
    test_ranked_for_table()
    test_nodes_in_vpn()
    test_bypass_rule_for_own_process()
    test_subnet_diversity()
    test_latency_matters_and_fast_https_not_lost()
    test_few_good_filled_only_to_minimum()
    test_slow_never_fill_the_group()
    test_unstable_go_last()
    test_app_routing_modes()
    test_pinned_and_countries()
    test_no_working_raises()
    print("\nВсе тесты singbox_config.py прошли.")

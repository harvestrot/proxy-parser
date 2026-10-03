"""Репутация: надёжность, чёрный список, «отдых», перепроверка проверенных."""
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import reputation as rp  # noqa: E402
from proxyparser.models import CheckResult, Proxy, ProxyType  # noqa: E402


def P(host, port=1080):
    return Proxy(host, port, ProxyType.SOCKS5, source="test")


def main():
    path = pathlib.Path(tempfile.mkdtemp()) / "rep.json"
    rep = rp.Reputation.load(path)
    now = 1_000_000.0

    good, flaky, dead, mitm = P("1.0.0.1"), P("1.0.0.2"), P("1.0.0.3"), P("1.0.0.4")
    for i in range(4):
        t = now + i * 600
        rep.update([
            CheckResult(good, True, latency_ms=300 + i * 10, speed_kbps=1000),
            CheckResult(flaky, i % 2 == 0, latency_ms=500, error=None if i % 2 == 0 else "timeout"),
            CheckResult(dead, False, error="порт закрыт"),
        ], t)
    rep.update([CheckResult(mitm, False, error="подменяет сертификат (1.1.1.1) — опасен: CERT")], now)

    e_good, e_flaky = rep.get(good), rep.get(flaky)
    assert e_good.ok == 4 and e_good.checks == 4 and e_good.reliability > 0.8
    assert 0.4 < e_flaky.reliability < 0.6
    assert e_good.speed_kbps == 1000 and e_good.latency_ms is not None
    print(f"OK: надёжность: стабильный {e_good.reliability:.2f}, «мигающий» {e_flaky.reliability:.2f}")

    assert rep.should_skip(mitm) and "чёрном списке" in rep.should_skip(mitm)
    print("OK: подменявший сертификат — в чёрном списке навсегда")

    fresh = P("1.0.0.9")
    rep.update([CheckResult(fresh, False, error="x")], now)
    assert rep.should_skip(fresh, now) is None  # один провал — ещё проверяем
    rep.update([CheckResult(fresh, False, error="x")], now + 600)
    assert "отдыхе" in (rep.should_skip(fresh, now + 601) or "")
    assert rep.should_skip(fresh, now + 600 + rp.COOLDOWN_SECONDS + 1) is None
    assert rep.should_skip(flaky, now + 3000) is None  # хоть раз работавший на отдых не уходит
    print("OK: ни разу не работавший после 2 провалов подряд отдыхает сутки, потом снова проверяется")

    proven = {p.address for p in rep.proven(now + 3000)}
    assert proven == {"1.0.0.1:1080", "1.0.0.2:1080"}, proven
    # через 48 ч «мигающий» уже не проверенный, а быстрый (1000 КБ/с) помнится неделю — см. ниже
    assert {p.address for p in rep.proven(now + 3000 + rp.PROVEN_MAX_AGE + 10_000)} == {"1.0.0.1:1080"}
    print("OK: «проверенные» (2+ успеха за 48 ч) перепроверяются, даже если пропали из источников")

    rep_fast = rp.Reputation(path=path.with_name("fast.json"))
    rep_fast.update([CheckResult(P("1.0.0.80"), True, latency_ms=130, speed_kbps=5600)], now)  # один успех, быстрый
    rep_fast.update([CheckResult(P("1.0.0.81"), True, latency_ms=130, speed_kbps=200)], now)   # один успех, медленный
    assert {p.address for p in rep_fast.proven(now + 5 * 24 * 3600)} == {"1.0.0.80:1080"}
    assert rep_fast.proven(now + rp.FAST_PROVEN_MAX_AGE + 1) == []
    node = Proxy("node.example.com", 443, ProxyType.VLESS, source="подписка",
                 link="vless://11111111-2222-3333-4444-555555555555@node.example.com:443?security=none")
    rep_fast.update([CheckResult(node, True, latency_ms=300, speed_kbps=2000)], now)
    rep_fast.save()
    again = {p.address: p for p in rp.Reputation.load(rep_fast.path).proven(now + 3600)}["node.example.com:443"]
    assert again.type == ProxyType.VLESS and again.link == node.link
    print("OK: узел VLESS помнится со своей ссылкой — перепроверяется, даже если пропал из подписки")
    print("OK: быстрый прокси (от 500 КБ/с) — «проверенный» после одной проверки и помнится неделю, "
          "даже если пропал из списков")

    r = CheckResult(good, True)
    rep.annotate(r)
    assert (r.rep_ok, r.rep_checks) == (4, 4)
    rep.remember_countries({"1.0.0.1": ("DE", "Germany")})
    rep.remember_networks({"1.0.0.1": ("isp", "AS29518 Bredband2 AB"), "1.0.0.2": (None, "")})
    rep.save()
    rep2 = rp.Reputation.load(path)
    assert rep2.get(good).ok == 4 and rep2.get(mitm).mitm and rep2.country_of("1.0.0.1") == ("DE", "Germany")
    assert rep2.network_of("1.0.0.1") == ("isp", "AS29518 Bredband2 AB")
    assert rep2.network_of("1.0.0.2") is None  # неизвестный тип сети не кешируется — спросим ещё раз
    e_dead = rep2.get(fresh)
    assert e_dead is not None and e_dead.fail_streak == 2 and e_dead.skip_until > now
    import json as _json
    raw = _json.loads(path.read_text(encoding="utf-8"))
    assert "1.0.0.9:1080" in "".join(raw["dead"]) and all("1.0.0.9" not in k for k in raw["entries"])
    print("OK: сохранение/загрузка, кеш стран и типов сети; мёртвые хранятся компактно и восстанавливаются")

    early = rep2.prune(now + rp.FORGET_DEAD_AFTER + 10_000)
    assert rep2.get(dead) is None and rep2.get(fresh) is None and rep2.get(good) is not None
    forgotten = early + rep2.prune(now + rp.FORGET_AFTER + 10_000)
    assert forgotten == 4 and rep2.get(mitm) is not None  # чёрный список не забывается
    print("OK: давно не встречавшиеся забываются, чёрный список — нет")

    path.write_text("{битый", encoding="utf-8")
    assert rp.Reputation.load(path).entries == {}
    print("OK: повреждённый файл -> чистая репутация, без падения")
    print("\nВсе тесты reputation.py прошли.")


if __name__ == "__main__":
    main()

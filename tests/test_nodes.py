"""Узлы VLESS / VMess / Trojan / Shadowsocks: разбор ссылок и подписок, outbound для sing-box."""
import base64
import json
import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import nodes  # noqa: E402
from proxyparser.models import ProxyType  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def vmess(**fields) -> str:
    j = {"v": "2", "ps": "имя", "add": "vm.example.com", "port": "443", "id": UUID, "aid": "0", "scy": "auto",
         "net": "ws", "type": "none", "host": "vm.example.com", "path": "/vm", "tls": "tls", "sni": "vm.example.com"}
    j.update(fields)
    return "vmess://" + b64(json.dumps(j))


LINKS = {
    "reality": (f"vless://{UUID}@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com&fp=firefox"
                "&pbk=AbCdEfGh&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#Имя"),
    "tls_ws_ed": f"vless://{UUID}@example.com:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws%3Fed%3D2048"
                 "&host=cdn.example.com&alpn=h2,http/1.1&allowInsecure=1#x",
    "grpc": f"vless://{UUID}@5.6.7.8:8443?security=none&type=grpc&serviceName=svc",
    "tag_in_param": f"vless://{UUID}@5.6.7.9:80?security=none&type=tcp%23%F0%9F%8E%97metka",
    "vmess": vmess(),
    "trojan": "trojan://pa%40ss@tr.example.com:443?sni=tr.example.com&type=ws&path=%2Ftr#t",
    "ss_sip002": "ss://" + b64("aes-256-gcm:secret") + "@9.9.9.9:8388#s",
    "ss_legacy": "ss://" + b64("chacha20-ietf-poly1305:pw:with:colons@8.8.8.8:443") + "#l",
    "ss_plain_userinfo": "ss://2022-blake3-aes-128-gcm:a2V5MTIzNDU2Nzg5MDEyMw%3D%3D@7.7.7.7:443",
}
BAD = {
    "xhttp": f"vless://{UUID}@1.2.3.4:443?security=tls&type=xhttp",
    "ss_plugin": "ss://" + b64("aes-256-gcm:x") + "@9.9.9.9:8388?plugin=obfs-local%3Bobfs%3Dhttp",
    "ss_old_cipher": "ss://" + b64("rc4-md5:x") + "@9.9.9.9:8388",
    "ipv6": f"vless://{UUID}@[2001:db8::1]:443?security=none",
    "private_ip": f"vless://{UUID}@10.0.0.1:443?security=none",
    "bad_flow": f"vless://{UUID}@1.2.3.4:443?security=tls&flow=xtls-rprx-vision-udp443",
    "reality_no_key": f"vless://{UUID}@1.2.3.4:443?security=reality&sni=x.com",
    "http_obfs": f"vless://{UUID}@1.2.3.4:443?type=tcp&headerType=http",
    "vmess_bad_cipher": vmess(scy="rc4"),
    "garbage": "vless://",
}


def test_links():
    n = {k: nodes.parse_link(v, "src") for k, v in LINKS.items()}

    r = n["reality"]
    assert (r.type, r.host, r.port, r.source, r.link) == (ProxyType.VLESS, "1.2.3.4", 443, "src", LINKS["reality"])
    ob = nodes.outbound(r)
    assert ob["type"] == "vless" and ob["uuid"] == UUID and ob["flow"] == "xtls-rprx-vision"
    assert ob["tls"]["reality"] == {"enabled": True, "public_key": "AbCdEfGh", "short_id": "6ba85179e30d4fc2"}
    assert ob["tls"]["server_name"] == "www.microsoft.com" and ob["tls"]["utls"]["fingerprint"] == "firefox"
    assert "transport" not in ob and nodes.label(r) == "Reality"

    ob = nodes.outbound(n["tls_ws_ed"])
    assert n["tls_ws_ed"].host == "example.com"
    assert ob["transport"] == {"type": "ws", "path": "/ws", "max_early_data": 2048,
                               "early_data_header_name": "Sec-WebSocket-Protocol",
                               "headers": {"Host": "cdn.example.com"}}, ob["transport"]
    assert ob["tls"]["insecure"] and ob["tls"]["alpn"] == ["h2", "http/1.1"] and "reality" not in ob["tls"]
    assert nodes.label(n["tls_ws_ed"]) == "TLS · ws"

    ob = nodes.outbound(n["grpc"])
    assert "tls" not in ob and ob["transport"] == {"type": "grpc", "service_name": "svc"}
    assert "transport" not in nodes.outbound(n["tag_in_param"])  # «type=tcp#метка» — метка отрезана

    ob = nodes.outbound(n["vmess"])
    assert n["vmess"].type == ProxyType.VMESS and n["vmess"].host == "vm.example.com"
    assert ob["security"] == "auto" and ob["alter_id"] == 0 and ob["tls"]["server_name"] == "vm.example.com"
    assert ob["transport"]["path"] == "/vm"

    ob = nodes.outbound(n["trojan"])
    assert ob["type"] == "trojan" and ob["password"] == "pa@ss" and ob["tls"]["enabled"]  # Trojan — всегда TLS
    assert ob["tls"]["server_name"] == "tr.example.com" and ob["transport"]["type"] == "ws"

    assert nodes.outbound(n["ss_sip002"]) == {"type": "shadowsocks", "server": "9.9.9.9", "server_port": 8388,
                                              "method": "aes-256-gcm", "password": "secret"}
    ob = nodes.outbound(n["ss_legacy"])
    assert (n["ss_legacy"].host, n["ss_legacy"].port) == ("8.8.8.8", 443) and ob["password"] == "pw:with:colons"
    ob = nodes.outbound(n["ss_plain_userinfo"])
    assert ob["method"] == "2022-blake3-aes-128-gcm" and ob["password"] == "a2V5MTIzNDU2Nzg5MDEyMw=="
    print("OK: VLESS (Reality, TLS+ws с ранними данными, gRPC), VMess, Trojan, Shadowsocks (3 формата) — "
          "в outbound sing-box")

    for name, link in BAD.items():
        try:
            nodes.parse_link(link)
        except ValueError:
            continue
        raise AssertionError(f"{name}: ссылка должна отбрасываться")
    print("OK: отбрасывается то, что sing-box не умеет или что нам не годится "
          f"({', '.join(BAD)})")


def test_subscription():
    good = [LINKS["reality"], LINKS["vmess"], LINKS["ss_sip002"]]
    text = "\n".join(good + [BAD["xhttp"], "мусор", "", LINKS["reality"].replace("#Имя", "#дубль")])
    for body in (text, b64(text), "\n".join(b64(text)[i:i + 76] for i in range(0, len(b64(text)), 76))):
        found = nodes.parse_subscription(body, "подписка")
        assert [p.address for p in found] == ["1.2.3.4:443", "vm.example.com:443", "9.9.9.9:8388"], found
    print("OK: подписка — обычная, в base64 и base64 с переносами строк; мусор и дубли отброшены")

    farm = "\n".join(f"vless://{UUID}@3.3.3.3:{1000 + i}?security=none" for i in range(10))
    many = "\n".join(f"vless://{UUID}@4.4.{i}.4:443?security=none" for i in range(50))
    collect = nodes.subscription_source("подписка", "https://x/sub", limit=20, rng=random.Random(1))
    got = collect(lambda url: farm + "\n" + many)
    assert len(got) == 20 and sum(p.host == "3.3.3.3" for p in got) <= 2, got
    assert all(p.source == "подписка" and p.link for p in got)
    try:
        nodes.subscription_source("пусто", "https://x/sub")(lambda url: "ничего")
        raise AssertionError("пустая подписка — ошибка источника")
    except RuntimeError:
        pass
    print("OK: источник-подписка — лимит, не больше 2 портов одного сервера, пустая — ошибка")


if __name__ == "__main__":
    test_links()
    test_subscription()
    print("\nВсе тесты nodes.py прошли.")

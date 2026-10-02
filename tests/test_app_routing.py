"""Настройки маршрутизации по приложениям и список запущенных программ."""
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import app_routing as ar  # noqa: E402


def main():
    tmp = pathlib.Path(tempfile.mkdtemp()) / "routing.json"
    assert ar.load(tmp).mode == ar.MODE_ALL and ar.load(tmp).apps == []
    print("OK: нет файла — весь трафик через прокси (как раньше)")

    steam = ar.app_for_exe("steam.exe")
    assert steam.title == "Steam" and steam.processes == ["steam.exe", "steamwebhelper.exe"]
    discord = ar.app_for_exe("Discord.exe")
    assert discord.title == "Discord" and discord.processes == ["Discord.exe"]
    custom = ar.app_for_exe("MyGame.exe", "Моя игра")
    assert custom.title == "Моя игра" and custom.processes == ["MyGame.exe"]
    print("OK: у известных программ подтягиваются все сетевые процессы (Steam — ещё steamwebhelper)")

    s = ar.RoutingSettings(ar.MODE_ONLY, [steam, discord, custom])
    ar.save(s, tmp)
    back = ar.load(tmp)
    assert back.to_dict() == s.to_dict()
    names = back.process_names()
    assert "Discord.exe" in names and "discord.exe" in names and "MyGame.exe" in names and "mygame.exe" in names
    assert back.describe() == "Через прокси: Steam, Discord, Моя игра"
    print("OK: настройки сохраняются и читаются; имена процессов — как в системе и в нижнем регистре")

    assert ar.RoutingSettings(ar.MODE_EXCEPT, []).effective_mode() == ar.MODE_ALL
    assert "напрямую" in ar.RoutingSettings(ar.MODE_ONLY, []).describe()
    print("OK: «кроме» с пустым списком = весь трафик; «только» с пустым — честно пишет, что всё напрямую")

    tmp.write_text(json.dumps({"mode": "weird", "apps": [
        {"title": "A", "processes": ["a.exe"]}, {"title": "A2", "processes": ["A.EXE"]},  # дубль
        {"processes": []}, "мусор", {"processes": ["b.exe"]},
    ]}), encoding="utf-8")
    s = ar.load(tmp)
    assert s.mode == ar.MODE_ALL and [a.title for a in s.apps] == ["A", "b.exe"], s
    tmp.write_bytes(b'{"mode": "only", "ap')
    assert ar.load(tmp).mode == ar.MODE_ALL
    print("OK: кривые и обрезанные настройки не роняют программу; дубли схлопываются")

    ps = json.dumps([
        {"p": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "d": "Google Chrome", "w": 1},
        {"p": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "d": "Google Chrome", "w": 0},
        {"p": r"C:\Windows\System32\svchost.exe", "d": "Хост-процесс", "w": 0},
        {"p": r"C:\Users\u\AppData\Local\Discord\app-1.0.9\Discord.exe", "d": "Discord", "w": 0},
        {"p": r"C:\Games\NoDesc.exe", "d": None, "w": 0},
        {"p": r"C:\Users\u\Telegram Desktop\Telegram.exe", "d": "Telegram Desktop", "w": 1},
    ])
    apps = ar.parse_running_apps(ps, skip_dirs=(r"C:\Windows",))
    assert [(a.title, a.exe, a.windowed) for a in apps] == [
        ("Google Chrome", "chrome.exe", True), ("Telegram Desktop", "Telegram.exe", True),
        ("Discord", "Discord.exe", False), ("NoDesc", "NoDesc.exe", False),
    ], apps
    assert ar.parse_running_apps(json.dumps({"p": r"C:\x\one.exe", "d": "", "w": 0}))[0].exe == "one.exe"
    assert ar.parse_running_apps("not json") == []
    print("OK: запущенные программы — по одной на .exe, системные скрыты, с окнами — первыми")
    print("\nВсе тесты app_routing.py прошли.")


if __name__ == "__main__":
    main()

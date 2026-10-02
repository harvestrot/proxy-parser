"""Настройки программы, скрипт автозапуска и «одна копия программы»."""
import json
import pathlib
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from proxyparser import app_settings as aps, autostart, single_instance  # noqa: E402


def test_settings():
    tmp = pathlib.Path(tempfile.mkdtemp()) / "settings.json"
    s = aps.load(tmp)
    assert (s.auto_connect, s.close_to_tray, s.auto_refresh_hours, s.pinned, s.countries) == (False, True, 3, None, [])
    print("OK: по умолчанию — без автоподключения, крестик в трей, фоновое обновление раз в 3 ч")

    s.auto_connect, s.auto_refresh_hours = True, 6
    s.pinned = {"address": "85.8.47.208:7080", "type": "HTTPS"}
    s.countries = ["se", "DE", "de"]
    aps.save(aps.from_dict(json.loads(json.dumps(s.__dict__))), tmp)
    back = aps.load(tmp)
    assert back.auto_connect and back.auto_refresh_hours == 6 and back.pinned_address == "85.8.47.208:7080"
    assert back.countries == ["DE", "SE"], back.countries
    print("OK: настройки сохраняются; коды стран приводятся к виду «DE», дубли убираются")

    tmp.write_text(json.dumps({"auto_refresh_hours": 5, "pinned": "строка", "countries": ["RUS", 7, "fr"],
                               "лишнее": 1}), encoding="utf-8")
    s = aps.load(tmp)
    assert s.auto_refresh_hours == 3 and s.pinned is None and s.countries == ["FR"], s
    tmp.write_bytes(b'{"auto_connect": tr')
    assert aps.load(tmp).auto_connect is False
    print("OK: кривой или обрезанный settings.json не роняет программу")


def test_autostart_script():
    exe_script = autostart.build_register_script(r"C:\Apps\ProxyParser.exe", [], r"C:\Apps")
    assert "-Argument '--autostart'" in exe_script, exe_script
    script = autostart.build_register_script(r"C:\Py\pythonw.exe", [r"C:\Program Files\it's me\gui.py"], r"C:\x")
    assert "-RunLevel Highest" in script and "-AllowStartIfOnBatteries" in script
    assert "-DontStopIfGoingOnBatteries" in script and "ExecutionTimeLimit ([TimeSpan]::Zero)" in script
    assert "it''s me" in script and "--autostart" in script and "PT15S" in script
    print("OK: задание автозапуска — с наивысшими правами, работает от батареи, без лимита в 72 ч")
    if sys.platform == "win32":  # синтаксис — настоящим парсером PowerShell (ничего не регистрируя)
        check = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:PP_SCRIPT,"
                 " [ref]$null, [ref]$e); exit $e.Count")
        env = {**__import__("os").environ, "PP_SCRIPT": script}
        rc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", check],
                            env=env, capture_output=True, timeout=60).returncode
        assert rc == 0, f"синтаксических ошибок PowerShell: {rc}"
        print("OK: скрипт автозапуска синтаксически верен (проверено парсером PowerShell)")


def test_single_instance():
    port = 48299
    first = single_instance.acquire(port=port)
    assert first is not None
    assert single_instance.acquire(port=port) is None, "вторая копия не должна занять порт"
    shown = threading.Event()
    single_instance.serve(first, shown.set)
    assert single_instance.notify_existing(port=port) and shown.wait(3)
    print("OK: вторая копия не запускается, а показывает окно первой")
    first.close()
    again = single_instance.acquire(wait_s=2, port=port)
    assert again is not None
    again.close()
    print("OK: после выхода первой копии порт свободен (перезапуск от администратора не ломается)")


if __name__ == "__main__":
    test_settings()
    test_autostart_script()
    test_single_instance()
    print("\nВсе тесты app_settings.py прошли.")

"""Автозапуск вместе с Windows — сразу с правами администратора, без окна UAC.

Обычный автозапуск (папка «Автозагрузка», ключ Run в реестре) запускает
программу с обычными правами, а VPN нужны права администратора — пришлось бы
каждый раз подтверждать окно UAC. Задание в планировщике Windows с «наивысшими
правами» запускается при входе в систему сразу как надо.

Задание создаётся через PowerShell (Register-ScheduledTask), а не schtasks:
у заданий по умолчанию два подвоха — на ноутбуке от батареи они не стартуют, а
через 72 часа работы Windows их принудительно завершает. Здесь оба отключены.
Создать и удалить задание с наивысшими правами можно только от администратора.
"""
from __future__ import annotations

import logging
import subprocess
import sys

from . import paths

log = logging.getLogger(__name__)

TASK_NAME = "ProxyParser VPN"
START_DELAY = "PT15S"  # дать сети подняться после входа в систему
AUTOSTART_ARG = "--autostart"


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def build_register_script(execute: str, args: list[str], workdir: str) -> str:
    """``execute`` + ``args`` — чем запускать окно (собранный exe или pythonw gui.py)."""
    argument = " ".join([f'"{a}"' for a in args] + [AUTOSTART_ARG])
    return "; ".join([
        "$ErrorActionPreference = 'Stop'",
        f"$a = New-ScheduledTaskAction -Execute {_ps_quote(execute)} -Argument {_ps_quote(argument)}"
        f" -WorkingDirectory {_ps_quote(workdir)}",
        "$u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
        "$t = New-ScheduledTaskTrigger -AtLogOn -User $u",
        f"$t.Delay = {_ps_quote(START_DELAY)}",
        "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest",
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"
        " -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew",
        f"Register-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -Action $a -Trigger $t -Principal $p"
        " -Settings $s -Description 'Proxy Parser: VPN через бесплатные прокси' -Force | Out-Null",
    ])


def _run(args: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _decode(raw: bytes) -> str:
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def is_enabled() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def enable() -> tuple[bool, str]:
    """Создать задание. Возвращает (получилось, текст ошибки)."""
    if sys.platform != "win32":
        return False, "автозапуск поддерживается только в Windows"
    execute, args = paths.launch_command()
    script = build_register_script(execute, args, str(paths.APP_DIR))
    try:
        proc = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script], timeout=60)
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    if proc.returncode != 0:
        return False, _decode(proc.stderr)[:300] or f"код {proc.returncode}"
    log.info("Автозапуск включён: задание «%s» в планировщике Windows", TASK_NAME)
    return True, ""


def disable() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "автозапуск поддерживается только в Windows"
    try:
        proc = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    if proc.returncode != 0 and is_enabled():
        return False, _decode(proc.stderr)[:300] or f"код {proc.returncode}"
    log.info("Автозапуск выключен")
    return True, ""

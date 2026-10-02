# start_vpn.ps1
# Включает системный VPN: поднимает TUN-интерфейс и заворачивает в него
# весь трафик системы через лучший рабочий прокси (с автопереключением).
#
# ОБЯЗАТЕЛЬНО от администратора — создание TUN-адаптера и правка
# таблицы маршрутизации требуют прав администратора на Windows:
#
#   powershell -ExecutionPolicy Bypass -File .\vpn\start_vpn.ps1
#
# Остановка: Ctrl+C в этом же окне — sing-box сам аккуратно снимет
# маршруты и закроет интерфейс. Не закрывай окно крестиком и не убивай
# процесс через диспетчер задач — тогда маршруты может не восстановить
# (на этот случай есть stop_vpn.ps1).

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Нужны права администратора: запусти PowerShell через 'Запуск от имени администратора' и повтори."
    exit 1
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $root "bin\sing-box.exe"
$config = Join-Path $root "config.json"

if (-not (Test-Path $exe)) {
    Write-Error "Не найден $exe — сначала запусти .\vpn\setup_vpn.ps1"
    exit 1
}
if (-not (Test-Path $config)) {
    Write-Error "Не найден $config — сначала запусти 'python main.py vpn-config' (а до этого 'python main.py all')"
    exit 1
}

Write-Host "Запускаю sing-box (Ctrl+C для остановки)..." -ForegroundColor Cyan
& $exe run -c $config

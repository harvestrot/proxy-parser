# stop_vpn.ps1
# Аварийная остановка, если start_vpn.ps1 запускали в фоне/окно закрыли
# крестиком вместо Ctrl+C. Предпочтительный способ остановки — Ctrl+C в
# окне start_vpn.ps1: тогда sing-box сам корректно снимает маршруты.
#
#   powershell -ExecutionPolicy Bypass -File .\vpn\stop_vpn.ps1

$proc = Get-Process -Name "sing-box" -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "sing-box не запущен."
    exit 0
}

Write-Warning "Принудительно останавливаю sing-box. Таблица маршрутизации могла не восстановиться — если после этого пропал интернет, перезапусти сетевой адаптер (или компьютер)."
$proc | Stop-Process -Force
Write-Host "Остановлено."

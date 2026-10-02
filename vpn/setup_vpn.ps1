# setup_vpn.ps1
# Одноразовая подготовка: скачивает последний релиз sing-box (Windows,
# amd64) и кладёт его в vpn\bin\sing-box.exe.
#
# Запускать ОТ ИМЕНИ АДМИНИСТРАТОРА (ПКМ по PowerShell -> "Запуск от
# имени администратора"), иначе дальше TUN-интерфейс не поднимется:
#
#   powershell -ExecutionPolicy Bypass -File .\vpn\setup_vpn.ps1

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Скрипт не запущен от администратора. Установить sing-box можно и так, но start_vpn.ps1 потом всё равно потребует админских прав для TUN-интерфейса."
}

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $root
$binDir = Join-Path $root "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# Если sing-box.exe уже где-то лежит рядом (например, скачан вручную
# раньше в папку вида sing-box-X.Y.Z-windows-amd64) — просто используем
# его и не качаем заново.
$existing = Get-ChildItem -Path $projectRoot -Filter "sing-box.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existing) {
    Write-Host "Нашёл уже скачанный $($existing.FullName) — использую его, повторно качать не буду."
    Copy-Item -Path $existing.FullName -Destination (Join-Path $binDir "sing-box.exe") -Force
    $dll = Join-Path $existing.DirectoryName "libcronet.dll"
    if (Test-Path $dll) {
        Copy-Item -Path $dll -Destination (Join-Path $binDir "libcronet.dll") -Force
    }
    Write-Host ""
    Write-Host "Готово: $binDir\sing-box.exe" -ForegroundColor Green
    Write-Host "Дальше:"
    Write-Host "  1) python main.py all          (собрать и проверить прокси)"
    Write-Host "  2) python main.py vpn-config   (сгенерировать vpn\config.json)"
    Write-Host "  3) .\vpn\start_vpn.ps1         (от администратора — включить VPN)"
    exit 0
}

Write-Host "Узнаю последнюю версию sing-box..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/SagerNet/sing-box/releases/latest" -Headers @{ "User-Agent" = "proxy-parser-claude" }
$asset = $release.assets | Where-Object { $_.name -match "windows-amd64.*\.zip$" } | Select-Object -First 1

if (-not $asset) {
    Write-Error "Не нашёл windows-amd64 .zip в последнем релизе sing-box (тег $($release.tag_name)). Зайди на https://github.com/SagerNet/sing-box/releases и скачай подходящий архив вручную в $binDir, распакуй и переименуй exe в sing-box.exe."
    exit 1
}

Write-Host "Нашёл: $($asset.name) (релиз $($release.tag_name))"
$zipPath = Join-Path $binDir $asset.name
Write-Host "Скачиваю в $zipPath ..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

$extractDir = Join-Path $binDir "extracted"
if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

$exe = Get-ChildItem -Path $extractDir -Filter "sing-box.exe" -Recurse | Select-Object -First 1
if (-not $exe) {
    Write-Error "В архиве не нашёлся sing-box.exe — распакуй $zipPath вручную и положи exe в $binDir\sing-box.exe"
    exit 1
}

Copy-Item -Path $exe.FullName -Destination (Join-Path $binDir "sing-box.exe") -Force
Remove-Item -Recurse -Force $extractDir
Remove-Item -Force $zipPath

Write-Host ""
Write-Host "Готово: $binDir\sing-box.exe ($($release.tag_name))" -ForegroundColor Green
Write-Host "Дальше:"
Write-Host "  1) python main.py all          (собрать и проверить прокси)"
Write-Host "  2) python main.py vpn-config   (сгенерировать vpn\config.json)"
Write-Host "  3) .\vpn\start_vpn.ps1         (от администратора — включить VPN)"

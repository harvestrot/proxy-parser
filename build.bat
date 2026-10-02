@echo off
rem Сборка Proxy Parser в один файл: dist\ProxyParser.exe
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Создаю окружение Python...
    py -m venv .venv 2>nul || python -m venv .venv
)

echo Ставлю зависимости и PyInstaller...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt "pyinstaller>=6.10"
if errorlevel 1 goto :fail

echo Собираю exe...
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean ProxyParser.spec
if errorlevel 1 goto :fail

echo Проверяю сборку...
"dist\ProxyParser.exe" --selfcheck "%TEMP%\proxyparser_selfcheck.json"
if errorlevel 1 goto :fail
type "%TEMP%\proxyparser_selfcheck.json"
echo.
echo Готово: dist\ProxyParser.exe
pause
exit /b 0

:fail
echo Сборка не удалась — см. сообщения выше.
pause
exit /b 1

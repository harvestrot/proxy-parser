@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem Первый запуск: создаём окружение и ставим зависимости (один раз)
if not exist ".venv\Scripts\pythonw.exe" (
    echo Создаю окружение Python...
    py -m venv .venv 2>nul || python -m venv .venv
    if not exist ".venv\Scripts\pythonw.exe" (
        echo Не получилось создать окружение. Установи Python 3.11+ с python.org
        echo ^(при установке отметь "Add python.exe to PATH"^) и запусти снова.
        pause
        exit /b 1
    )
)

rem Зависимости ставим, если их ещё не ставили или requirements.txt изменился
rem (в .deps_ok лежит копия списка, с которым ставили в прошлый раз)
fc /b requirements.txt ".venv\.deps_ok" >nul 2>&1
if errorlevel 1 (
    echo Устанавливаю зависимости...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
    if errorlevel 1 (
        echo Ошибка установки зависимостей — см. сообщение выше.
        pause
        exit /b 1
    )
    copy /y requirements.txt ".venv\.deps_ok" >nul
)

start "" ".venv\Scripts\pythonw.exe" "%~dp0gui.py" %*

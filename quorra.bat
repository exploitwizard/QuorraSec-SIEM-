@echo off
:: Quorra SIEM — Windows launcher
:: Double-click this file or run it from the command prompt.
::
:: Usage:
::   quorra.bat                  Start with auto-selected port
::   quorra.bat --no-browser     Start without opening a browser
::   quorra.bat --port 8080      Start on a specific port
::   quorra.bat --help           Show all options

cd /d "%~dp0"

:: Prefer the virtual-environment Python if it exists
if exist "venv\Scripts\python.exe" (
    set PYTHON=venv\Scripts\python.exe
) else (
    set PYTHON=python
)

:: Load .env if present
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" if not "%%A:~0,1%"=="#" set %%A=%%B
    )
)

echo Starting Quorra SIEM...
"%PYTHON%" quorra.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo Quorra exited with error code %ERRORLEVEL%.
    pause
)

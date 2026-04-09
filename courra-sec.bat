@echo off
:: Courra-Sec — Windows launcher
:: Double-click this file or run it from the command prompt.
::
:: Usage:
::   courra-sec.bat                  Start with auto-selected port
::   courra-sec.bat --no-browser     Start without opening a browser
::   courra-sec.bat --port 8080      Start on a specific port
::   courra-sec.bat --help           Show all options

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

echo Starting Courra-Sec...
"%PYTHON%" courra-sec.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo Courra-Sec exited with error code %ERRORLEVEL%.
    pause
)

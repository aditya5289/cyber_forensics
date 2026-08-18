@echo off
rem ===================================================================
rem  ARGUS Forensics - Windows launcher
rem  Double-click this file to start the application.
rem ===================================================================
setlocal
title ARGUS Forensics
cd /d "%~dp0"

rem Find a usable Python. The py launcher is preferred because it picks the
rem newest installed version; fall back to whatever 'python' resolves to.
set "PYEXE="
where py >nul 2>&1 && set "PYEXE=py -3"
if not defined PYEXE (
    where python >nul 2>&1 && set "PYEXE=python"
)
if not defined PYEXE (
    echo.
    echo   ----------------------------------------------------------------
    echo    ARGUS cannot start: Python was not found on this computer.
    echo   ----------------------------------------------------------------
    echo.
    echo    Install Python 3.10 or newer from:
    echo        https://www.python.org/downloads/
    echo.
    echo    IMPORTANT: during installation, tick the box
    echo        "Add Python to PATH"
    echo    then run this launcher again.
    echo.
    pause
    exit /b 1
)

rem Already running on the default port?
netstat -ano | findstr /R /C:":8742 .*LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo.
    echo   ARGUS is already running.
    echo   Switch back to your browser tab, or close "ARGUS Forensics"
    echo   from the taskbar and run this launcher again.
    echo.
    timeout /t 4
    exit /b 0
)

echo.
echo   Starting ARGUS Forensics...
echo   Your browser will open in a moment.
echo   ARGUS runs minimized in the taskbar — close that window to stop it.
echo.

rem Detached + minimized so this launcher can exit and you do not need to
rem keep a console open while you work. argus_app.py opens the browser with
rem the correct session token.
start "ARGUS Forensics" /min %PYEXE% "%~dp0argus_app.py" --quiet %*

echo   Done. You can close this window.
timeout /t 3 >nul
endlocal
exit /b 0

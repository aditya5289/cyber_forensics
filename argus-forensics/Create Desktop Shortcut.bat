@echo off
rem Creates "ARGUS Forensics" on your Desktop — one double-click from there.
cd /d "%~dp0"
cscript //nologo "%~dp0Create Desktop Shortcut.vbs"
echo.
echo   Desktop shortcut created:  ARGUS Forensics
echo   Double-click it anytime to start the workbench.
echo.
timeout /t 4

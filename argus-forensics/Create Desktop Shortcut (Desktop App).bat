@echo off
REM Create a desktop shortcut to ARGUS Forensics desktop app (after cargo tauri build)
setlocal
set "EXE=%~dp0src-tauri\target\release\argus-forensics.exe"
set "DESKTOP=%USERPROFILE%\Desktop"
set "SHORTCUT=%DESKTOP%\ARGUS Forensics.lnk"

if not exist "%EXE%" (
  echo Build the desktop app first:
  echo   scripts\build-desktop.ps1
  echo or:
  echo   cargo tauri build
  pause
  exit /b 1
)

powershell -NoProfile -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('%SHORTCUT%');" ^
  "$s.TargetPath = '%EXE%';" ^
  "$s.WorkingDirectory = '%~dp0src-tauri\target\release';" ^
  "$s.Description = 'ARGUS Forensics — mobile forensic workbench';" ^
  "$s.Save()"

echo Created: %SHORTCUT%
pause

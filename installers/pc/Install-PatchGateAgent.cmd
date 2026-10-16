@echo off
rem PatchGate: install the Tactical agent on this bank PC (double-click). Asks for administrator rights,
rem then runs Install-PatchGateAgent.ps1 with patchgate-pc.json from THIS folder.
rem Run it from a local folder or a \server\share path (mapped drive letters are not visible after elevation).
rem Log: C:\ProgramData\PatchGate\agent-install.log
setlocal
set "HERE=%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  echo Asking for administrator rights...
  set "PG_SELF=%~f0"
  powershell.exe -NoProfile -Command "Start-Process -FilePath $env:PG_SELF -Verb RunAs"
  exit /b
)
if not exist "%HERE%patchgate-pc.json" (
  echo FAILED - patchgate-pc.json not found next to this file: %HERE%
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%Install-PatchGateAgent.ps1" -ConfigFile "%HERE%patchgate-pc.json"
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%

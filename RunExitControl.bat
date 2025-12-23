@echo off
setlocal

REM Launch ExitControl with elevation by double-clicking this file.
set SCRIPT_DIR=%~dp0
set SCRIPT_PATH=%SCRIPT_DIR%ExitControl.ps1

if not exist "%SCRIPT_PATH%" (
  echo ExitControl.ps1 not found in %SCRIPT_DIR%
  pause
  exit /b 1
)

powershell -NoLogo -NoProfile -Command ^
  "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File','\"%SCRIPT_PATH%\"'"

endlocal

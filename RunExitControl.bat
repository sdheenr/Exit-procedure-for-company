@echo off
setlocal

REM Double-click launcher: starts ExitControl.ps1 elevated.

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_PATH=%SCRIPT_DIR%ExitControl.ps1"

if not exist "%SCRIPT_PATH%" (
  echo.
  echo ExitControl.ps1 was not found in:
  echo   %SCRIPT_DIR%
  echo.
  echo Keep RunExitControl.bat in the same folder as ExitControl.ps1.
  echo.
  pause
  exit /b 1
)

REM The script path is handed over as an environment variable rather than
REM substituted into the command line, so spaces, ampersands and quotes in the
REM folder name cannot break the invocation. [char]34 builds the quotes that
REM -File needs without embedding literal quotes in this batch line.
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; try { Start-Process -FilePath 'PowerShell' -Verb RunAs -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File ' + $q + $env:SCRIPT_PATH + $q) -ErrorAction Stop } catch { Write-Host $_.Exception.Message; exit 1 }"

if errorlevel 1 (
  echo.
  echo Could not start ExitControl with administrator rights.
  echo If a User Account Control prompt appeared, it was declined.
  echo.
  pause
  exit /b 1
)

endlocal

@echo off
setlocal

set "FR_WINPE_MODE=1"
set "APP_ROOT=%~dp0"
set "APP_EXE=%APP_ROOT%FileRecovery.WindowsApp.exe"
set "LOG_PATH=X:\file-recovery-winpe-startup.log"

echo [%date% %time%] WinPE startup script invoked.>%LOG_PATH%
echo [%date% %time%] Launch path: %APP_EXE%>>%LOG_PATH%

if not exist "%APP_EXE%" (
  echo [%date% %time%] ERROR: App executable not found.>>%LOG_PATH%
  echo FileRecovery.WindowsApp.exe not found at %APP_EXE%
  pause
  exit /b 1
)

start "" "%APP_EXE%"
echo [%date% %time%] App launch requested.>>%LOG_PATH%

exit /b 0

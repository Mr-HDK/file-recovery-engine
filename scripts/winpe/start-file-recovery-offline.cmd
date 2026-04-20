@echo off
setlocal

set "FR_WINPE_MODE=1"
set "APP_ROOT=%~dp0"
set "APP_EXE=%APP_ROOT%FileRecovery.WindowsApp.exe"
set "APP_DLL=%APP_ROOT%FileRecovery.WindowsApp.dll"
set "DOTNET_EXE=%APP_ROOT%dotnet\dotnet.exe"
set "LOG_PATH=X:\file-recovery-winpe-startup.log"
if not exist "X:\" set "LOG_PATH=%SystemDrive%\file-recovery-winpe-startup.log"

echo [%date% %time%] WinPE startup script invoked.>%LOG_PATH%
echo [%date% %time%] App root: %APP_ROOT%>>%LOG_PATH%
echo [%date% %time%] Candidate EXE: %APP_EXE%>>%LOG_PATH%
echo [%date% %time%] Candidate DLL: %APP_DLL%>>%LOG_PATH%
echo [%date% %time%] Candidate dotnet: %DOTNET_EXE%>>%LOG_PATH%

if not exist "%APP_EXE%" (
  if exist "%APP_DLL%" (
    if exist "%DOTNET_EXE%" (
      echo [%date% %time%] EXE missing, launching DLL with local dotnet.>>%LOG_PATH%
      start "" "%DOTNET_EXE%" "%APP_DLL%"
      echo [%date% %time%] App launch requested via dotnet host.>>%LOG_PATH%
      exit /b 0
    )

    echo [%date% %time%] ERROR: EXE missing and local dotnet host missing.>>%LOG_PATH%
    echo App launch failed: %APP_EXE% missing and %DOTNET_EXE% missing.
    pause
    exit /b 1
  )

  echo [%date% %time%] ERROR: App executable and DLL not found.>>%LOG_PATH%
  echo App launch failed: FileRecovery.WindowsApp.exe and FileRecovery.WindowsApp.dll not found under %APP_ROOT%
  pause
  exit /b 1
)

start "" "%APP_EXE%"
echo [%date% %time%] App launch requested.>>%LOG_PATH%

exit /b 0

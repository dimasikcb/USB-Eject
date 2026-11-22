@echo off
setlocal EnableExtensions
set "SCRIPT=%~dp0USB-Eject.ps1"
if not exist "%SCRIPT%" (
    echo [!] USB-Eject.ps1 not found next to USB-Eject.bat
    pause
    exit /b 1
)

rem --- Admin check (fltmc requires elevation) ---
fltmc >nul 2>&1
if %errorlevel%==0 goto :run

echo Requesting administrator rights (UAC prompt)...
if "%~1"=="" (
    powershell -NoProfile -Command "try { Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\"' } catch { Write-Host 'Cancelled. Administrator rights are required.' }"
) else (
    powershell -NoProfile -Command "try { Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\" \"%~1\"' } catch { Write-Host 'Cancelled. Administrator rights are required.' }"
)
exit /b 0

:run
if "%~1"=="" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" "%~1"
)

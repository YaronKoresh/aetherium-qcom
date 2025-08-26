@echo off
REM Aetherium Q-Com Launcher for Windows

cd /d %~dp0

echo Launching Aetherium Q-Com...
echo.

REM This command assumes 'aetherium-qcom' is in the system's PATH,
REM which the installer should handle.
aetherium-qcom

echo.
echo Aetherium Q-Com has been closed.
pause

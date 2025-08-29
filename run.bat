@echo off
cd /d %~dp0

echo Launching Aetherium Q-Com...
echo.

py -m aetherium_qcom_platform

echo.
echo Aetherium Q-Com has been closed.
pause

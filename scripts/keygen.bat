@echo off
cd /d %~dp0

echo.
echo [AETHERIUM Q-COM]
echo Generating new developer master keys...
echo.

py -m aetherium_qcom keygen

echo.
echo Key generation complete.
pause
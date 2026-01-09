@echo off
cd /d %~dp0

echo.
echo [AETHERIUM Q-COM]
echo Signing project source code...
echo.

py -m aetherium_qcom sign

echo.
echo Project signing complete.
pause
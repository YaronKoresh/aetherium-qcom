@echo off
REM Aetherium Q-Com Launcher for Windows
echo Checking for Python installation...

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in your system's PATH.
    echo Please install the latest version of Python from python.org
    echo Make sure to check the box "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Python found.
echo Installing/Updating Aetherium Q-Com from GitHub...

python -m pip install --upgrade git+https://github.com/YaronKoresh/aetherium-qcom.git

if %errorlevel% neq 0 (
    echo [ERROR] Installation failed. Please check your internet connection and pip setup.
    pause
    exit /b 1
)

echo Installation complete.
echo Launching Aetherium Q-Com...
echo.

aetherium-qcom

echo.
echo Aetherium Q-Com has been closed.
pause

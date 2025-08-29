@echo off
cd /d %~dp0

echo Checking for prerequisites...

where py >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Python not found. Administrator privileges are required to install it.
    goto install_python_prompt
)
echo  - Python: Found.

where ffmpeg >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] FFmpeg not found. Administrator privileges are required to install it.
    goto install_ffmpeg_prompt
)
echo  - FFmpeg: Found.

where clang >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Clang C++ Compiler not found. It will be installed automatically.
    goto install_clang_prompt
)
echo  - C++ Compiler (Clang): Found.

goto install_package_standard

:install_python_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_python'"
    exit /b
)
echo [INFO] Now running as Administrator to install Python...
set "PYTHON_INSTALLER_URL=https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
set "INSTALLER_PATH=%TEMP%\python_installer.exe"
echo Downloading Python 3.11.5 installer...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%PYTHON_INSTALLER_URL%', '%INSTALLER_PATH%')"
if %errorlevel% neq 0 ( goto end_error )
start /wait %INSTALLER_PATH% /quiet InstallAllUsers=1 PrependPath=1
del "%INSTALLER_PATH%"
echo [SUCCESS] Python has been installed. Please re-run this script.
goto end_success

:install_ffmpeg_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_ffmpeg'"
    exit /b
)
echo [INFO] Now running as Administrator to install FFmpeg...
echo [INFO] Attempting to install using Winget (Windows Package Manager)...
winget install --id=Gyan.FFmpeg.Essentials -e --accept-source-agreements --accept-package-agreements
if %errorlevel% equ 0 (
    echo [SUCCESS] FFmpeg has been installed via Winget. Please re-run this script.
    goto end_success
)
echo [WARN] Winget installation failed. Attempting manual download...
set "FFMPEG_URL=https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"
set "ZIP_PATH=%TEMP%\ffmpeg.zip"
set "EXTRACT_PATH=%TEMP%\ffmpeg_extracted"
echo Downloading latest FFmpeg build...
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%FFMPEG_URL%', '%ZIP_PATH%')"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download FFmpeg.
    goto end_error
)
echo Extracting FFmpeg...
powershell -Command "Expand-Archive -Path '%ZIP_PATH%' -DestinationPath '%EXTRACT_PATH%' -Force"
md "%ProgramFiles%\ffmpeg" >nul 2>nul
for /d %%d in ("%EXTRACT_PATH%\*") do (
    set "FFMPEG_DIR=%%d"
)
robocopy "%FFMPEG_DIR%\bin" "%ProgramFiles%\ffmpeg" /E /MOVE
echo Adding FFmpeg to the system PATH...
setx /M PATH "%PATH%;%ProgramFiles%\ffmpeg"
del "%ZIP_PATH%"
rmdir /s /q "%EXTRACT_PATH%"
echo [SUCCESS] FFmpeg has been installed manually. Please re-run this script from a new command prompt.
goto end_success

:install_clang_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_clang'"
    exit /b
)
echo [INFO] Now running as Administrator to install Clang...
set "CLANG_INSTALLER_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe"
set "INSTALLER_PATH=%TEMP%\clang_installer.exe"
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('%CLANG_INSTALLER_URL%', '%INSTALLER_PATH%')"
if %errorlevel% neq 0 ( goto end_error )
echo Starting Clang installation (this may take a few minutes)...
setx /M LLVM_INSTALL_DIR "%ProgramFiles%\LLVM"
start /wait %INSTALLER_PATH% /S /D="%LLVM_INSTALL_DIR%"
setx /M PATH "%PATH%;%LLVM_INSTALL_DIR%\bin"
del "%INSTALLER_PATH%"
echo [SUCCESS] Clang C++ Compiler has been installed. Please re-run this script from a new command prompt.
goto end_success

:install_package_standard
echo Installing/Updating Aetherium Q-Com and all dependencies...
py -m pip install -e .
if %errorlevel% equ 0 (
    goto install_complete
)
powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_package_admin'"
exit /b

:install_package_as_admin
echo Now running as Administrator. Retrying installation...
py -m pip install -e .
if %errorlevel% neq 0 (
    goto end_error
)

:install_complete
echo.
echo [SUCCESS] Aetherium Q-Com has been installed successfully.
goto end_success

:end_error
echo.
echo [INSTALLATION FAILED] An error occurred.
echo.
pause
exit /b 1

:end_success
pause
exit /b 0

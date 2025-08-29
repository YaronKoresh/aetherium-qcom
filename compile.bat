@echo off
cd /d %~dp0

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo.
echo # Aetherium Q-Com Nuitka Builder
echo # =================================
echo.

echo [STEP 1/3] Installing Nuitka...
py -m pip install --upgrade nuitka
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Nuitka.
    goto end_error
)
echo  - Nuitka is up to date.

echo.
echo [STEP 2/3] Checking for MSVC Build Tools...
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 >nul 2>&1
    if %errorlevel% equ 0 (
        echo  - MSVC Build Tools are already installed.
        goto compile_nuitka
    )
)

echo  - MSVC Build Tools not found. Starting automatic installation...
echo  - This process may take several minutes and requires an internet connection.
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('https://aka.ms/vs/17/release/vs_BuildTools.exe', '.\vs_BuildTools.exe')"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to download Visual Studio Build Tools installer.
    goto end_error
)

start /wait .\vs_BuildTools.exe --quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] MSVC Build Tools installation failed.
    del .\vs_BuildTools.exe
    goto end_error
)

del .\vs_BuildTools.exe
echo  - MSVC Build Tools installed successfully.

:compile_nuitka
echo.
echo [STEP 3/3] Starting Nuitka compilation...
echo.
py -m nuitka ^
    --onefile ^
    --standalone ^
    --windows-console-mode=disable ^
    --msvc=latest ^
    -j %NUMBER_OF_PROCESSORS% ^
    --enable-plugin=pyside6 ^
    --include-module=collections ^
    --include-module=xml ^
    --include-package=pydub ^
    --include-package=moviepy ^
    --include-package=kademlia ^
    --include-package=rpcudp ^
    --include-package=cryptography ^
    --include-package=pqcrypto ^
    --include-package=packaging ^
    --include-package=tqdm ^
    --include-package=proglog ^
    --include-module=olefile ^
    --include-module=defusedxml ^
    --include-module=pillow_heif ^
    --include-module=PIL.Image ^
    .\aetherium_qcom_platform.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Nuitka compilation failed.
    goto end_error
)

echo.
echo #######################################################
echo # [SUCCESS] Compilation complete!
echo # Your single-file executable is located in:
echo # %cd%\aetherium_qcom_platform.dist\aetherium_qcom_platform.exe
echo #######################################################
echo.
goto end_success

:end_error
echo.
echo [BUILD FAILED] An error occurred.
echo.
pause
exit /b 1

:end_success
pause
exit /b 0

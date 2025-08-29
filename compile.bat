@echo off
cd /d %~dp0

echo.
echo # Aetherium Q-Com Nuitka Builder
echo # =================================
echo.

echo [STEP 1/2] Installing Nuitka...
py -m pip install --upgrade nuitka
if %errorlevel% equ 0 (
    echo  - Dependencies installed successfully.
    goto compile_nuitka
)
powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_deps_admin'"
echo [INFO] Now running as Administrator to install Nuitka...
py -m pip install --upgrade nuitka
if %errorlevel% equ 0 (
    echo  - Dependencies installed successfully with admin rights.
    goto compile_nuitka
)
goto end_error

:compile_nuitka
echo.
echo [STEP 2/2] Starting Nuitka compilation...
echo.
py -m nuitka ^
    --onefile ^
    --standalone ^
    --windows-console-mode=disable ^
    --clang ^
    -j %NUMBER_OF_PROCESSORS% ^
    --plugin-enable=multiprocessing ^
    --include-module=fcntl ^
    --include-module=collections.abc ^
    --include-module=collections ^
    --include-module=xml.dom.XML_NAMESPACE ^
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

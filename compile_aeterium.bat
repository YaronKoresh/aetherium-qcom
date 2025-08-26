@echo off
REM Nuitka Builder for Aetherium Q-Com
REM Automatically checks for and installs Python, Git, and the Clang C++ Compiler.

cd /d %~dp0

REM == Argument handler for elevated re-launch ==
if "%1"=="install_python" goto install_python_logic
if "%1"=="install_git" goto install_git_logic
if "%1"=="install_clang" goto install_clang_logic
if "%1"=="install_deps_admin" goto install_deps_as_admin

REM == Main script entry point ==
echo.
echo # Aetherium Q-Com Nuitka Builder
echo # =================================
echo.

REM == 1. Prerequisite Checks ==
echo [STEP 1/5] Checking for prerequisites...

:check_python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Python not found. Administrator privileges are required to install it.
    goto install_python_prompt
)
echo  - Python: Found.

:check_git
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Git not found. Administrator privileges are required to install it.
    goto install_git_prompt
)
echo  - Git: Found.

:check_compiler
where clang >nul 2>nul
if %errorlevel% neq 0 (
    echo [INFO] Clang C++ Compiler not found. It will be installed automatically.
    goto install_clang_prompt
)
echo  - C++ Compiler (Clang): Found.
goto install_dependencies

:install_python_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrative privileges for Python installation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_python'"
    exit /b
)
goto install_python_logic

:install_python_logic
echo [INFO] Now running as Administrator to install Python...
set "PYTHON_INSTALLER_URL=https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe"
set "INSTALLER_PATH=%TEMP%\python_installer.exe"
echo Downloading Python 3.11.5 installer...
powershell -Command "Invoke-WebRequest -Uri '%PYTHON_INSTALLER_URL%' -OutFile '%INSTALLER_PATH%'"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download Python installer.
    goto end_error
)
echo Starting Python installation...
start /wait %INSTALLER_PATH% /quiet InstallAllUsers=1 PrependPath=1
del "%INSTALLER_PATH%"
echo [SUCCESS] Python has been installed. Please re-run this script to continue.
goto end_success

:install_git_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrative privileges for Git installation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_git'"
    exit /b
)
goto install_git_logic

:install_git_logic
echo [INFO] Now running as Administrator to install Git...
set "GIT_INSTALLER_URL=https://github.com/git-for-windows/git/releases/download/v2.41.0.windows.3/Git-2.41.0.3-64-bit.exe"
set "INSTALLER_PATH=%TEMP%\git_installer.exe"
echo Downloading Git for Windows installer...
powershell -Command "Invoke-WebRequest -Uri '%GIT_INSTALLER_URL%' -OutFile '%INSTALLER_PATH%'"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download Git installer.
    goto end_error
)
echo Starting Git installation...
start /wait %INSTALLER_PATH% /VERYSILENT /NORESTART
del "%INSTALLER_PATH%"
echo [SUCCESS] Git has been installed. Please re-run this script to continue.
goto end_success

:install_clang_prompt
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Requesting administrative privileges for Clang C++ Compiler installation...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_clang'"
    exit /b
)
goto install_clang_logic

:install_clang_logic
echo [INFO] Now running as Administrator to install Clang...
echo [INFO] This will download and install the LLVM/Clang compiler tools.
set "CLANG_INSTALLER_URL=https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/LLVM-18.1.8-win64.exe"
set "INSTALLER_PATH=%TEMP%\clang_installer.exe"
echo Downloading LLVM/Clang installer...
powershell -Command "Invoke-WebRequest -Uri '%CLANG_INSTALLER_URL%' -OutFile '%INSTALLER_PATH%'"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download the Clang installer.
    goto end_error
)
echo Starting Clang installation (this may take a few minutes)...
set "ADD_TO_PATH_ALL_USERS=1"
start /wait %INSTALLER_PATH% /S /D=%ProgramFiles%\LLVM
del "%INSTALLER_PATH%"
echo.
echo [SUCCESS] Clang C++ Compiler has been installed.
echo [IMPORTANT] You MUST close this window and run the script again from a NEW command prompt for the changes to take effect.
goto end_success

:install_dependencies
echo.
echo [STEP 2/5] Installing Nuitka and project dependencies...
python -m pip install --upgrade nuitka
python -m pip install --upgrade --force-reinstall git+https://github.com/YaronKoresh/aetherium-qcom.git
if %errorlevel% equ 0 (
    echo  - Dependencies installed successfully.
    goto clone_source
)
echo [INFO] Standard installation failed, likely due to permissions. Retrying as Administrator...
powershell -Command "Start-Process '%~f0' -Verb RunAs -ArgumentList 'install_deps_admin'"
exit /b

:install_deps_as_admin
echo [INFO] Now running as Administrator to install dependencies...
python -m pip install --upgrade nuitka
python -m pip install --upgrade --force-reinstall git+https://github.com/YaronKoresh/aetherium-qcom.git
if %errorlevel% neq 0 (
    echo [ERROR] Installation failed even with administrator privileges.
    goto end_error
)
echo  - Dependencies installed successfully with admin rights.
echo.
pause
exit /b 0

:clone_source
echo.
echo [STEP 3/5] Cloning latest source code from GitHub...
if exist "aetherium-qcom" (
    echo  - Removing existing source folder...
    rmdir /s /q aetherium-qcom
)
git clone https://github.com/YaronKoresh/aetherium-qcom.git
if %errorlevel% neq 0 (
    echo [ERROR] Failed to clone the repository.
    goto end_error
)
cd aetherium-qcom
echo  - Source code cloned successfully.
echo.

REM == 4. Locate Gradio Data Files ==
echo [STEP 4/5] Locating Gradio's web interface files...
for /f "delims=" %%i in ('python -c "import gradio, os; print(os.path.dirname(gradio.__file__))"') do set "GRADIO_PATH=%%i"
if not defined GRADIO_PATH (
    echo [ERROR] Could not determine the path for the Gradio library.
    goto end_error
)
echo  - Gradio path found at: %GRADIO_PATH%
echo.

REM == 5. Run Nuitka Compilation ==
echo [STEP 5/5] Starting Nuitka compilation. This will take a long time...
echo.
python -m nuitka ^
    --onefile ^
    --standalone ^
    --windows-disable-console ^
    --clang ^
    -j %NUMBER_OF_PROCESSORS% ^
    --plugin-enable=numpy ^
    --plugin-enable=pillow ^
    --plugin-enable=pyqt5 ^
    --include-data-dir="%GRADIO_PATH%/templates=gradio/templates" ^
    --include-data-dir="%GRADIO_PATH%/themes=gradio/themes" ^
    aetherium_qcom_platform.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Nuitka compilation failed. Please review the output above for errors.
    goto end_error
)

echo.
echo #######################################################
echo # [SUCCESS] Compilation complete!
echo #
echo # Your single-file executable is located in:
echo # %cd%\aetherium_qcom_platform.dist\aetherium_qcom_platform.exe
echo #######################################################
echo.
goto end_success

:end_error
echo.
echo [BUILD FAILED] An error occurred. Please check the messages above.
echo.
pause
exit /b 1

:end_success
pause
exit /b 0
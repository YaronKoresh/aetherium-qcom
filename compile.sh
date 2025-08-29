#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

request_sudo() {
    if [[ $EUID -ne 0 ]]; then
        info "Administrator (sudo) privileges are required to install missing tools."
        sudo -v
        if [ $? -ne 0 ]; then
            error "Sudo privileges not granted. Aborting."
        fi
    fi
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        INSTALL_CMD="sudo apt-get install -y"
        UPDATE_CMD="sudo apt-get update"
    elif command -v yum &> /dev/null; then
        INSTALL_CMD="sudo yum install -y"
    elif command -v pacman &> /dev/null; then
        INSTALL_CMD="sudo pacman -Syu --noconfirm"
    elif command -v brew &> /dev/null; then
        INSTALL_CMD="brew install"
    else
        error "Could not detect a supported package manager (apt, yum, pacman, brew)."
    fi
}

echo
echo "# Aetherium Q-Com Nuitka Builder"
echo "# ================================"
echo

echo "[STEP 1/2] Installing Nuitka..."
python3 -m pip install --upgrade nuitka
success " - Dependencies installed successfully."

echo
echo "[STEP 2/2] Starting Nuitka compilation..."
echo

PLATFORM_OPTIONS=""
if [[ "$(uname)" == "Darwin" ]]; then
    PLATFORM_OPTIONS="--macos-create-app-bundle"
    NUM_CORES=$(sysctl -n hw.ncpu)
else
    NUM_CORES=$(nproc)
fi

python3 -m nuitka \
    --onefile \
    --standalone \
    --clang \
    -j "$NUM_CORES" \
    --enable-plugin=pyside6 \
    --include-module=collections \
    --include-module=xml \
    --include-package=pydub \
    --include-package=moviepy \
    --include-package=kademlia \
    --include-package=rpcudp \
    --include-package=cryptography \
    --include-package=pqcrypto \
    --include-package=packaging \
    --include-package=tqdm \
    --include-package=proglog \
    --include-module=olefile \
    --include-module=defusedxml \
    --include-module=pillow_heif \
    --include-module=PIL.Image \
    $PLATFORM_OPTIONS \
    ./aetherium_qcom_platform.py

if [ $? -ne 0 ]; then
    error "Nuitka compilation failed. Please review the output above for errors."
fi

echo
echo "#######################################################"
success "[SUCCESS] Compilation complete!"
echo "#"
if [[ "$(uname)" == "Darwin" ]]; then
    echo "# Your application bundle is located in:"
    echo "# $(pwd)/aetherium_qcom_platform.app"
else
    echo "# Your single-file executable is located in:"
    echo "# $(pwd)/aetherium_qcom_platform.bin"
fi
echo "#######################################################"
echo

read -p "Press Enter to exit..."
exit 0

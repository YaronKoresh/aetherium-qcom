#!/bin/sh
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
        BUILD_DEPS="build-essential yasm nasm libx264-dev libx265-dev libnuma-dev libvpx-dev libfdk-aac-dev libmp3lame-dev libopus-dev"
    elif command -v yum &> /dev/null; then
        INSTALL_CMD="sudo yum install -y"
        BUILD_DEPS="nasm yasm-devel libx264-devel libx265-devel libvpx-devel libfdk-aac-devel lame-devel opus-devel"
    elif command -v pacman &> /dev/null; then
        INSTALL_CMD="sudo pacman -Syu --noconfirm"
        BUILD_DEPS="base-devel yasm nasm x264 x265 libvpx fdk-aac lame opus"
    elif command -v brew &> /dev/null; then
        INSTALL_CMD="brew install"
        BUILD_DEPS="yasm nasm x264 x265 libvpx fdk-aac lame opus"
    else
        error "Could not detect a supported package manager (apt, yum, pacman, brew)."
    fi
}

echo
echo "# Aetherium Q-Com Installer"
echo "# ========================="
echo

info "Checking for prerequirements..."
NEEDS_INSTALL=""

if ! command -v python3 &> /dev/null; then
    info " - Python3: Not found. It will be installed."
    NEEDS_INSTALL="$NEEDS_INSTALL python3 python3-pip"
fi

if ! command -v clang &> /dev/null; then
    info "Clang C++ Compiler not found. It will be installed."
    NEEDS_INSTALL="$NEEDS_INSTALL clang"
else
    success " - C++ Compiler (Clang): Found."
fi

if ! command -v git &> /dev/null; then
    info " - Git: Not found. It will be installed."
    NEEDS_INSTALL="$NEEDS_INSTALL git"
fi

if ! command -v make &> /dev/null || ! command -v gcc &> /dev/null; then
    info " - Build tools (make, gcc): Not found. They will be installed."
    NEEDS_INSTALL="$NEEDS_INSTALL build-essential"
fi

if ! command -v ffmpeg &> /dev/null; then
    info " - FFmpeg: Not found. It will be compiled from source."
    FFMPEG_COMPILE=1
else
    success " - FFmpeg: Found."
fi

if [ -n "$NEEDS_INSTALL" ]; then
    request_sudo
    detect_package_manager

    [ -n "$UPDATE_CMD" ] && $UPDATE_CMD

    info "Installing missing base prerequirements..."
    $INSTALL_CMD $NEEDS_INSTALL
    success "Base prerequirements installed. Please re-run this script."
    exit 0
fi

if [ "$FFMPEG_COMPILE" = "1" ]; then
    info "Installing FFmpeg build dependencies..."
    request_sudo
    detect_package_manager
    [ -n "$UPDATE_CMD" ] && $UPDATE_CMD
    $INSTALL_CMD $BUILD_DEPS

    info "Cloning FFmpeg source code..."
    TEMP_DIR=$(mktemp -d)
    git clone --depth 1 https://git.ffmpeg.org/ffmpeg.git "$TEMP_DIR"
    cd "$TEMP_DIR"

    info "Configuring FFmpeg build..."
    ./configure --enable-gpl --enable-libx264 --enable-libx265 --enable-libvpx --enable-libfdk-aac --enable-libmp3lame --enable-libopus --enable-nonfree
    
    info "Compiling FFmpeg (this will take a very long time)..."
    make -j$(nproc)

    info "Installing FFmpeg..."
    sudo make install
    
    cd -
    rm -rf "$TEMP_DIR"
    success "FFmpeg has been compiled and installed."
fi

info "Installing/Updating Aetherium Q-Com..."
python3 -m pip install -e .
if [ $? -ne 0 ]; then
    error "Installation of Aetherium Q-Com failed."
fi

success "Aetherium Q-Com has been installed successfully."
info "You can now run the application using the 'run.sh' script or by typing 'aetherium-qcom'."

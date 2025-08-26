#!/bin/sh

info() {
    printf '\033[1;34m[INFO]\033[0m %s\n' "$1"
}

error() {
    printf '\033[1;31m[ERROR]\033[0m %s\n' "$1"
}

success() {
    printf '\033[1;32m[SUCCESS]\033[0m %s\n' "$1"
}

ensure_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        info "Administrator privileges are required. Requesting with sudo..."
        sudo sh "$0" --sudo-run
        exit $?
    fi
}

install_python() {
    info "Python3 not found. Attempting to install it..."
    ensure_sudo

    case "$(uname)" in
        Linux)
            if command -v apt-get >/dev/null 2>&1; then
                info "Debian/Ubuntu based system detected. Using apt-get..."
                apt-get update && apt-get install -y python3 python3-pip python3-venv
            elif command -v dnf >/dev/null 2>&1; then
                info "Fedora/RHEL based system detected. Using dnf..."
                dnf install -y python3 python3-pip
            elif command -v yum >/dev/null 2>&1; then
                info "CentOS/RHEL based system detected. Using yum..."
                yum install -y python3 python3-pip
            else
                error "Unsupported Linux distribution. Please install Python 3 and pip manually."
                exit 1
            fi
            ;;
        Darwin)
            info "macOS detected."
            if ! command -v brew >/dev/null 2>&1; then
                error "Homebrew not found. Please install it first from https://brew.sh"
                exit 1
            fi
            info "Using Homebrew to install Python..."
            brew install python
            ;;
        *)
            error "Unsupported operating system: $(uname). Please install Python 3 and pip manually."
            exit 1
            ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        error "Python installation failed. Please try installing it manually."
        exit 1
    fi

    success "Python has been installed."
}

install_package() {
    info "Installing/Updating Aetherium Q-Com from GitHub..."
    python3 -m pip install --upgrade --force-reinstall "git+https://github.com/YaronKoresh/aetherium-qcom.git"
    
    if [ $? -ne 0 ]; then
        info "Standard installation failed, likely due to permissions. Retrying as Administrator..."
        ensure_sudo
        python3 -m pip install --upgrade --force-reinstall "git+https://github.com/YaronKoresh/aetherium-qcom.git"
        if [ $? -ne 0 ]; then
            error "Installation failed even with administrator privileges."
            exit 1
        fi
    fi
}

main() {
    info "Checking for Python installation..."
    if ! command -v python3 >/dev/null 2>&1; then
        install_python
        info "Please re-run this script to continue with the Aetherium Q-Com installation."
        exit 0
    else
        info "Python found."
        install_package
        success "Aetherium Q-Com has been installed successfully."
        info "You can now run the application using the 'run_aeterium.sh' script."
    fi
}

if [ "$1" = "--sudo-run" ]; then
    install_package
    success "Dependencies installed with administrator privileges."
    exit 0
else
    main
fi

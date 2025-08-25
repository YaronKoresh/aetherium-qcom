#!/bin/bash
# Aetherium Q-Com Launcher for Linux & macOS

echo "Checking for Python 3 installation..."

if ! command -v python3 &> /dev/null
then
    echo "[ERROR] Python 3 could not be found."
    echo "Please install Python 3 using your system's package manager."
    echo "e.g., on Debian/Ubuntu: sudo apt-get install python3 python3-pip"
    echo "e.g., on Fedora: sudo dnf install python3 python3-pip"
    exit 1
fi

echo "Python 3 found."
echo "Installing/Updating Aetherium Q-Com from GitHub..."

python3 -m pip install --upgrade --force-reinstall git+https://github.com/YaronKoresh/aetherium-qcom.git

if [ $? -ne 0 ]; then
    echo "[ERROR] Installation failed. Please check your internet connection and pip setup."
    exit 1
fi

echo "Installation complete."
echo "Launching Aetherium Q-Com..."
echo ""

# Check if the command is in the path, if not, try the local user bin
if ! command -v aetherium-qcom &> /dev/null
then
    ~/.local/bin/aetherium-qcom
else
    aetherium-qcom
fi

echo ""
echo "Aetherium Q-Com has been closed."

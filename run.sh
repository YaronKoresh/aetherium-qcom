#!/bin/sh

info() {
    printf '\033[1;34m[INFO]\033[0m %s\n' "$1"
}

info "Launching Aetherium Q-Com..."
printf '\n'

python3 -m aetherium_qcom_platform

printf '\n'
info "Aetherium Q-Com has been closed."

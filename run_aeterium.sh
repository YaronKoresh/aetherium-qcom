#!/bin/sh

info() {
    printf '\033[1;34m[INFO]\033[0m %s\n' "$1"
}

info "Launching Aetherium Q-Com..."
printf '\n'

if [ -f "$HOME/.local/bin/aetherium-qcom" ]; then
    "$HOME/.local/bin/aetherium-qcom"
else
    aetherium-qcom
fi

printf '\n'
info "Aetherium Q-Com has been closed."

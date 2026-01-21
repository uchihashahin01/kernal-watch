#!/bin/bash

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "Detected OS: $OS"

if [[ "$OS" == "Ubuntu" || "$OS" == "Debian GNU/Linux" || "$OS" == "Kali GNU/Linux" ]]; then
    echo "Installing dependencies for Debian/Ubuntu/Kali..."
    sudo apt-get update
    sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc libbpf-dev
else
    echo "Unsupported OS: $OS"
    echo "Please install bpfcc-tools, linux-headers, python3-bpfcc, and libbpf-dev manually."
    exit 1
fi

echo "Setup complete."

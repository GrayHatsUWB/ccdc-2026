#!/bin/bash

# check_git.sh
# Usage: ./$1Check.sh

echo "Checking if $1 is installed..."

if command -v $1 >/dev/null 2>&1; then
    echo "$1 is installed."
    $1 --version
else
    echo "$1 is not installed."

    # Try to install depending on OS
    if [ -f /etc/debian_version ]; then
        echo "Installing $1 via apt..."
        sudo apt install -y $1
    elif [ -f /etc/redhat-release ]; then
        echo "Installing $1 via yum..."
        sudo yum install -y $1
    elif [ -f /etc/fedora-release ]; then
        echo "Installing $1 via dnf..."
        sudo dnf install -y $1
    elif [ -f /etc/arch-release ]; then
        echo "Installing $1 via pacman..."
        sudo pacman -S $1 --noconfirm
    else
        echo "Unsupported OS. Please install $1 manually."
        exit 1
    fi

    # Verify installation
    if command -v $1 >/dev/null 2>&1; then
        echo "$1 successfully installed."
        $1 --version
    else
        echo "$1 installation failed."
    fi
fi

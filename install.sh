#!/bin/bash

# ANSI color codes
G="\033[1;32m"
Y="\033[1;33m"
W="\033[0m"

echo -e "${Y}[*] Rayan-Suite Installer starting...${W}"

# Update and install dependencies
echo -e "${Y}[*] Installing core dependencies (python, git, whois, etc)...${W}"
pkg update -y && pkg upgrade -y
pkg install python git whois libjpeg-turbo libxml2 libxslt -y

# Install pip dependencies
echo -e "${Y}[*] Installing Python libraries (requests, pillow, etc)...${W}"
pip install requests beautifulsoup4 Pillow paramiko

# Create a runnable command
echo -e "${Y}[*] Creating the 'rayan' command...${W}"
# Get the full path to the script
SCRIPT_PATH=$(pwd)/rayan.py
# Create a command file in the bin directory
echo "python $SCRIPT_PATH \"\$@\"" > $PREFIX/bin/rayan
chmod +x $PREFIX/bin/rayan

echo -e "${G}[+] Installation Complete!${W}"
echo -e "${G}[+] You can now run the tool from anywhere by typing:${W}"
echo -e "${C}rayan${W}"
echo -e "${Y}Please restart Termux for the command to be available.${W}"

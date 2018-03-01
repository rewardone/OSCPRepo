#!/bin/sh
#This script will do basic setup to make sure everything is in place
#This should would on default Kali installation
#TODO every once in a while, check for updates to SecLists and fuzzdb

echo "Downloading things..."
echo "Install new software: Shutter, exiftool, gobuster, git"
apt-get update
apt-get install -y shutter exiftool gobuster git

echo "Cloning Impacket"
git clone https://github.com/CoreSecurity/impacket.git /root/Documents/Impacket

echo "Cloning Vulners"
git clone https://github.com/vulnersCom/nmap-vulners.git /root/Documents/Vulners

echo "Cloning OSCPRepo"
git clone https://github.com/rewardone/OSCPRepo.git /root/Documents/OSCPRepo

echo "Cloning Vulners exploit database/search tool"
git clone https://github.com/vulnersCom/getsploit.git /root/Documents/Getsploit

echo "Processing actions..."
echo "Setup install Impacket"
chmod +x /root/Documents/Impacket/setup.py && /root/Documents/Impacket/./setup.py install

echo "Copy vulners to nmap scripts location"
cp /root/Documents/Vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse

echo "Copy getsploit to /usr/local/sbin for PATH"
cp /root/Documents/Getsploit/getsploit.py /usr/local/sbin

echo "Setup OSCPRepo"
cp -r /root/Documents/OSCPRepo/scripts /root/scripts
cp -r /root/Documents/OSCPRepo/lists /root/lists

echo "Make sure metasploit is ready to go"
service postgresql start
msfdb reinit




echo "Optional packages you might utilize in the future"
echo "apt-get install automake"

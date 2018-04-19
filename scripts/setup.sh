#!/bin/sh
#This script will do basic setup to make sure everything is in place
#This should would on default Kali installation

echo "### Downloading things...### \n\n"
echo "Install new software: Shutter, exiftool, gobuster, git"
apt-get update
apt-get install -y shutter exiftool gobuster git

echo "\nCloning Impacket \n"
direc=/root/Documents/Impacket
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/CoreSecurity/impacket.git $direc; fi

echo "\nCloning Vulners.nse script \n"
direc=/root/Documents/Vulners
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/vulnersCom/nmap-vulners.git $direc; fi

echo "\nCloning OSCPRepo \n"
direc=/root/Documents/OSCPRepo
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rewardone/OSCPRepo.git $direc; fi

echo "\nCloning Vulners exploit database/search tool \n"
direc=/root/Documents/Getsploit
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/vulnersCom/getsploit.git $direc; fi

echo "\nCloning PowershellEmpire\n"
direc=/root/Documents/Empire
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/EmpireProject/Empire.git $direc; fi

echo "\nCloning PowerSploit\n"
direc=/root/Documents/PowerSploit
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/PowerShellMafia/PowerSploit.git $direc; fi

echo "\n ### Processing actions...### \n\n"
echo "Setup install Impacket"
chmod +x /root/Documents/Impacket/setup.py && cd /root/Documents/Impacket && ./setup.py install

echo "\nCopy vulners to nmap scripts location \n"
cp /root/Documents/Vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse

echo "\nCopy getsploit to /usr/local/sbin for PATH \n"
cp /root/Documents/Getsploit/getsploit/getsploit.py /usr/local/sbin

echo "\nSetup OSCPRepo \n"
cp -r /root/Documents/OSCPRepo/scripts /root/
cp -r /root/Documents/OSCPRepo/lists /root/

echo "\nSetup Empire\n"
/root/Documents/Empire/setup/./install.sh

echo "\nDownloading additional lists: secLists fuzzdb naughtystrings payloadallthethings probable-wordlists\n"
direc=/root/lists/secLists
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/danielmiessler/SecLists.git $direc; fi
direc=/root/lists/fuzzdb
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/fuzzdb-project/fuzzdb.git $direc; fi
direc=/root/lists/naughty
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/minimaxir/big-list-of-naughty-strings.git $direc; fi
direc=/root/lists/payloadsAllTheThings
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git $direc; fi
direc=/root/lists/probableWordlists
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/berzerk0/Probable-Wordlists.git $direc; fi

echo "\nMake sure Metasploit is ready to go \n"
service postgresql start
msfdb reinit

echo "\nEdit dotdotpwn so you don't have to press 'ENTER' to start it \n"
sed -e "s/<STDIN>;/#<STDIN>;/" /usr/share/dotdotpwn/dotdotpwn.pl > /usr/share/dotdotpwn/dotdotpwn_TMP && mv /usr/share/dotdotpwn/dotdotpwn_TMP /usr/share/dotdotpwn/dotdotpwn.pl
chmod +x /usr/share/dotdotpwn/dotdotpwn.pl
direc=/usr/share/dotdotpwn/Reports
if [ ! -d "$direc" ]; then mkdir /usr/share/dotdotpwn/Reports; fi


echo "\n ### Optional packages you might utilize in the future ### \n"
echo "apt-get install automake"

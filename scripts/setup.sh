#!/bin/sh
#This script will do basic setup to make sure everything is in place
#This should would on default Kali installation
#
# Other notes
# shutter preferences: hide on first launch
# terminal preferences: Dark theme
# latest version of firefox, firefox bookmarks and extensions (foxyproxy)
# favorites menu (atom, firefox, keepnote, shutter)
#
# If in a VM and Copy/Paste is NOT working: apt-get install open-vm-tools open-vm-desktop
# and then reboot!!
#

echo "### Downloading things...### \n\n"
echo "Install new software: atom crackmapexec exiftool gobuster git nbtscan-unixwiz shutter"
curl -L https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] https://packagecloud.io/AtomEditor/atom/any/ any main" > /etc/apt/sources.list.d/atom.list'
apt-get update
apt-get install -y atom crackmapexec exiftool gobuster git nbtscan-unixwiz shutter

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

echo "\nSetup Getsploit\n"
cd /root/Documents/Getsploit && chmod +x setup.py && ./setup.py install

echo "\nSetup OSCPRepo \n"
cp -r /root/Documents/OSCPRepo/scripts /root/
cp -r /root/Documents/OSCPRepo/lists /root/

echo "\nSetup Empire\n"
#Empire calls ./setup from ./install, so needs to be in its directory
cd /root/Documents/Empire/setup && chmod +x setup_database.py && ./install.sh

echo "\nDownloading additional lists: secLists fuzzdb naughtystrings payloadallthethings probable-wordlists\n"
webDirec=/root/lists/Web
direc=/root/lists/secLists
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/danielmiessler/SecLists.git $direc; fi
ln -s $direc/Discovery/Web-Content $webDirec
direc=/root/lists/fuzzdb
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/fuzzdb-project/fuzzdb.git $direc; fi
direc=/root/lists/naughty
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/minimaxir/big-list-of-naughty-strings.git $direc; fi
direc=/root/lists/payloadsAllTheThings
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git $direc; fi
direc=/root/lists/Password/probableWordlists
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/berzerk0/Probable-Wordlists.git $direc; fi
direc=/root/lists/Password/passphrases
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/initstring/passphrase-wordlist.git $direc; fi

echo "\nMake sure Metasploit is ready to go \n"
systemctl start postgresql
msfdb reinit

echo "\nUpdating exploit-db, getsploit (vulners), and nmap scripts \n"
searchsploit -u
getsploit -u
nmap --script-updatedb

echo "\nEditing dotdotpwn so you don't have to press 'ENTER' to start it \n"
sed -e "s/<STDIN>;/#<STDIN>;/" /usr/share/dotdotpwn/dotdotpwn.pl > /usr/share/dotdotpwn/dotdotpwn_TMP && mv /usr/share/dotdotpwn/dotdotpwn_TMP /usr/share/dotdotpwn/dotdotpwn.pl
chmod +x /usr/share/dotdotpwn/dotdotpwn.pl
direc=/usr/share/dotdotpwn/Reports
if [ ! -d "$direc" ]; then mkdir /usr/share/dotdotpwn/Reports; fi


echo "\n ### Optional packages you might utilize in the future ### \n"
echo "apt-get install automake"

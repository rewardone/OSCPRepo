#!/bin/sh
#
# If in a VM and Copy/Paste is NOT working: apt-get install open-vm-tools open-vm-desktop
# and then reboot!!
#

echo "### Downloading things...### \n\n"
#Packages for crackmapexec: libssl-dev libffi-dev python-dev build-essential
echo "Install new software: atom build-essential bloodhound crackmapexec exiftool gobuster git nbtscan-unixwiz nfs-common flameshot libffi-dev libldap2-dev libsasl2-dev libssl-dev powershell-preview python-argcomplete python-dev"
curl -L https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] https://packagecloud.io/AtomEditor/atom/any/ any main" > /etc/apt/sources.list.d/atom.list'
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/debian/stretch/prod stretch main" >> /etc/apt/sources.list.d/microsoft.list'
apt-get update
apt-get install -y atom crackmapexec exiftool gobuster git nbtscan-unixwiz nfs-common flameshot libldap2-dev libsasl2-dev powershell-preview python-argcomplete

echo "\nCloning ADLdapEnum\n"
direc=/root/Documents/ADLdapEnum
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/CroweCybersecurity/ad-ldap-enum.git $direc; fi

echo "\nCloning CrackMapExec (master branch (v4 +))\n"
direc=/root/Documents/CrackMapExec
if [ -d "$direc" ]; then cd $direc && git pull; else git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec $direc; fi

echo "\nCloning Impacket \n"
direc=/root/Documents/Impacket
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/CoreSecurity/impacket.git $direc; fi

echo "\nCloning John Jumbo\n"
direc=/root/Documents/JohnJumbo
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/magnumripper/JohnTheRipper.git $direc; fi

echo "\nCloning LdapDD\n"
direc=/root/Documents/LdapDD
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/dirkjanm/ldapdomaindump.git $direc; fi

echo "\nCloning Nishang\n"
direc=/root/Documents/Nishang
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/samratashok/nishang.git $direc; fi

echo "\nCloning Nullinux\n"
direc=/root/Documents/Nullinux
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/m8r0wn/nullinux.git $direc; fi

echo "\nDownloading latest Oracle Database Attack Tool\n"
odat=`curl https://github.com/quentinhardy/odat/releases/latest -L --max-redirs 1 | grep -i "quentinhardy/odat/releases/download" | grep "x86_64" | cut -d '"' -f 2`
wget http://github.com$odat -O ~/Downloads/odat.zip

echo "\nCloning OSCPRepo \n"
direc=/root/Documents/OSCPRepo
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rewardone/OSCPRepo.git $direc; fi

echo "\nCloning Parameth\n"
direc=/root/Documents/Parameth
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/maK-/parameth.git $direc; fi

echo "\nCloning PEDA\n"
direc=/root/Documents/Peda
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/longld/peda.git $direc; fi
echo "source $direc/peda.py" >> ~/.gdbinit

echo "\nCloning PowerCat\n"
direc=/root/Documents/PowerCat
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/besimorhino/powercat.git $direc; fi

echo "\nCloning PowershellEmpire\n"
direc=/root/Documents/Empire
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/EmpireProject/Empire.git $direc; fi

echo "\nCloning PowerSploit\n"
direc=/root/Documents/PowerSploit
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/PowerShellMafia/PowerSploit.git -b dev $direc; fi

echo "\nCloning Python PTY Shells\n"
direc=/root/Documents/PythonPTYShells
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/infodox/python-pty-shells.git $direc; fi

echo "\nCloning ShellPop\n"
direc=/root/Documents/ShellPop
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/0x00-0x00/ShellPop.git $direc; fi

echo "\nCloning VHostScan\n"
direc=/root/Documents/VHostScan
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/codingo/VHostScan.git $direc; fi

echo "\nCloning Vulners.nse script \n"
direc=/root/Documents/Vulners
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/vulnersCom/nmap-vulners.git $direc; fi

echo "\nCloning Vulners exploit database/search tool \n"
direc=/root/Documents/Getsploit
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/vulnersCom/getsploit.git $direc; fi

#CMS Specific Updates
mkdir /root/Documents/CMSScanners 2>/dev/null

echo "\nCloning Joomscan\n"
direc=/root/Documents/CMSScanners/Joomscan
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rezasp/joomscan.git $direc; fi

echo "\nCloning JoomVS\n"
direc=/root/Documents/CMSScanners/JoomVS
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rastating/joomlavs.git $direc; fi

echo "\nCloning WPScan\n"
direc=/root/Documents/CMSScanners/WPScan
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/wpscanteam/wpscan-v3.git $direc; fi

echo "\nCloning Droopescan\n"
direc=/root/Documents/CMSScanners/Droopescan
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/droope/droopescan.git $direc; fi


#Local Enumerators. Can probably take out of OSCPRepo...
direc="/root/Documents/Local Info Enum"
mkdir $direc 2>/dev/null
direc="/root/Documents/Local Info Enum/Linux"
mkdir $direc 2>/dev/null
direc="/root/Documents/Local Info Enum/Windows"
mkdir $direc 2>/dev/null
#ensure directories are created before pulling into them
sleep 1

echo "\nCloning LinEnum\n"
direc="/root/Documents/Local Info Enum/Linux/RebootLinEnum"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rebootuser/LinEnum.git $direc; fi

echo "\nCopy Personal LinEnum\n"
direc="/root/Documents/Local Info Enum/Linux/"
cp "/root/Documents/OSCPRepo/Local Info Enum/LinEnum.sh" $direc

echo "\nCloning HostRecon\n"
direc="/root/Documents/Local Info Enum/Windows/HostRecon"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/dafthack/HostRecon.git $direc; fi

echo "\nCloning HostEnum\n"
direc="/root/Documents/Local Info Enum/Windows/HostEnum"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/threatexpress/red-team-scripts.git $direc; fi

echo "\nCloning WindowsEnum\n"
direc="/root/Documents/Local Info Enum/Windows/WindowsEnum"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/azmatt/windowsEnum $direc; fi

##TODO copy seatbelt

#Priv Esc Checkers. Can probably take out of OSCPRepo...
direc="/root/Documents/Priv Esc Checks"
mkdir $direc 2>/dev/null
direc="/root/Documents/Priv Esc Checks/Linux"
mkdir $direc 2>/dev/null
direc="/root/Documents/Priv Esc Checks/Windows"
mkdir $direc 2>/dev/null
#ensure directories are created before pulling into them
sleep 1

echo "\nCloning Linux-Exploit-Suggester\n"
direc="/root/Documents/Priv Esc Checks/Linux/linux-exploit-suggester"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/mzet-/linux-exploit-suggester.git $direc; fi


echo "\nCloning Perl Linux-Exploit-Suggester\n"
direc="/root/Documents/Priv Esc Checks/Linux/perl-linux-exploit-suggester"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/jondonas/linux-exploit-suggester-2.git $direc; fi

mkdir /root/Documents/Exploits 2>/dev/null
echo "\nCloning SecWiki-Windows-Kernel-Exploits\n"
direc=/root/Documents/Exploits/SecWiki-Windows-Kernel-Exploits
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/SecWiki/windows-kernel-exploits.git $direc; fi
cp -r $direc/win-exp-suggester /root/Documents/Priv\ Esc\ Checks/Windows/

echo "\nCloning Sherlock\n"
direc="/root/Documents/Priv Esc Checks/Windows/Sherlock"
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/rasta-mouse/Sherlock.git $direc; fi



echo "\n ### Processing actions...### \n\n"



echo "\nSetup ADLDAP\n"
cd /root/Documents/ADLdapEnum && pip install python-ldap && chmod +x ad-ldap-enum.py

echo "\nSetup CrackMapExec\n"
pip install --user pipenv
cd /root/Documents/CrackMapExec && pipenv install
pipenv shell
python setup.py install
exit

echo "\nSetup Empire\n"
#Empire calls ./setup from ./install, so needs to be in its directory
cd /root/Documents/Empire/setup && chmod +x setup_database.py && ./install.sh

echo "\nSetup Getsploit\n"
cd /root/Documents/Getsploit && chmod +x setup.py && ./setup.py install

echo "Setup install Impacket"
chmod +x /root/Documents/Impacket/setup.py && cd /root/Documents/Impacket && ./setup.py install

echo "\nBuilding John Jumbo\n"
if [ ! -f ~/Documents/JohnJumbo/run/john ]; then cd /root/Documents/JohnJumbo/src && ./configure && make; fi

echo "\nSetup LdapDD\n"
cd /root/Documents/LdapDD && chmod +x setup.py && chmod +x ldapdomaindump.py && python setup.py install

echo "\nSetup Nullinux\n"
cp -p /root/Documents/Nullinux/nullinux.py /usr/local/bin

echo "\nSetup ODAT\n"
mkdir /root/Documents/ODAT
unzip ~/Downloads/odat.zip -d /root/Documents/ODAT && rm ~/Downloads/odat.zip
cd /root/Documents/ODAT && mv odat*/* .

echo "\nSetup OSCPRepo \n"
pip install colorama
rm -rf /root/scripts/*
cp -r /root/Documents/OSCPRepo/scripts /root/
cp -r /root/Documents/OSCPRepo/lists /root/

echo "\nSetup Parameth\n"
cd /root/Documents/Parameth && pip install -U -r requirements.txt

echo "\nSetup Shellpop\n"
cd /root/Documents/ShellPop && pip install -r requirements.txt && chmod +x setup.py && python setup.py install

echo "\nSetup VHostScan\n"
cd /root/Documents/VHostScan && python3 -m pip install -r requirements.txt 2&>/dev/null
python3 -m pip install python-levenshtein 2&>/dev/null
cd /root/Documents/VHostScan && cat setup.py | sed -e 's/NUM_INSTALLED/num_installed/g' 1>/dev/null 2>/dev/null && python3 setup.py install

echo "\nCopy vulners to nmap scripts location \n"
cp /root/Documents/Vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse

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

echo "\nSetup Sparta for use with reconscan \n"
mv /usr/share/sparta/app/settings.py /usr/share/sparta/app/settings_orig.py
mv /usr/share/sparta/controller/controller.py /usr/share/sparta/controller/controller_orig.py
mv /etc/sparta.conf /etc/sparta_orig.conf
cp /root/Documents/OSCPRepo/scripts/random/Sparta/settings.py /usr/share/sparta/app/settings.py
cp /root/Documents/OSCPRepo/scripts/random/Sparta/controller.py /usr/share/sparta/controller/controller.py
cp /root/Documents/OSCPRepo/scripts/random/Sparta/sparta.conf /etc/sparta.conf

echo "\n ### Optional packages you might utilize in the future ### \n"
echo "apt-get install automake remmina freerdpx11 alacarte shutter"
echo "Shutter has been removed from Kali due to dependencies, find an alternative (currently FlameShot)"
echo "Keepnote may be removed from latest Kali as well. Source: http://keepnote.org/download/keepnote_0.7.8-1_all.deb"

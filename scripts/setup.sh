#!/bin/sh
#
# If in a VM and Copy/Paste is NOT working: 
# apt-get install open-vm-tools open-vm-desktop
# and then reboot!!
#

# This will be a standalone script for reconscan only
# Another script will be created for 'full' provisioning 

echo "### Downloading things...### \n\n"
echo "Install new software: vscode build-essential bloodhound crackmapexec exiftool gobuster git nbtscan-unixwiz nfs-common flameshot libffi-dev libldap2-dev libsasl2-dev libssl-dev powershell-preview python-argcomplete python-dev"

apt-get update 
apt install -y curl gnupg apt-transport-https

#vscode dependencies
curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/packages.microsoft.gpg
install -o root -g root -m 644 /tmp/packages.microsoft.gpg /usr/share/keyrings/
rm /tmp/packages.microsoft.gpg

sh -c 'echo "deb [arch=amd64 signed-by=/usr/share/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-buster-prod buster main" > /etc/apt/sources.list.d/microsoft.list'

apt-get update 
apt-get install -y code build-essential crackmapexec flameshot gobuster git nbtscan-unixwiz nfs-common nishang libimage-exiftool-perl libldap2-dev libsasl2-dev odat powercat powershell powershell-empire powersploit python-argcomplete python3-ldapdomaindump

# Clone <project> <dir> <parent_dir>
cloneProject()
{
    if [ ! -d "$3" ]; then mkdir -p $3; fi
    echo "\nCloning $2"
    d="$3/$2"
    if [ -d "$d" ]; then cd $d && git pull; else git clone $1 $d; fi
}

#optionals:
#https://github.com/byt3bl33d3r/CrackMapExec already get this in the apt install
#https://github.com/magnumripper/JohnTheRipper.git don't really 'need' jumbo
#echo "\nBuilding John Jumbo\n"
#if [ ! -f ~/Documents/JohnJumbo/run/john ]; then cd /root/Documents/JohnJumbo/src && ./configure && make; fi
#https://github.com/longld/peda.git don't really 'need' peda
#echo "source $direc/peda.py" >> ~/.gdbinit

one='/opt'
two='/opt/CMSScanners'
three='/root/Documents'

cloneProject 'https://github.com/CroweCybersecurity/ad-ldap-enum.git' 'ADLdapEnum' $one
echo "\nSetup ADLDAP\n"
cd "$one/ADLdapEnum" && pip install python-ldap && chmod +x ad-ldap-enum.py

cloneProject 'https://github.com/CoreSecurity/impacket.git' 'Impacket' $one
echo "Setup install Impacket"
cd "$one/Impacket" && chmod +x setup.py && ./setup.py install

cloneProject 'https://github.com/dirkjanm/ldapdomaindump.git' 'LdapDD' $one
echo "\nSetup LdapDD\n"
cd "$one/LdapDD" && chmod +x setup.py && chmod +x ldapdomaindump.py && ./setup.py install

cloneProject 'https://github.com/m8r0wn/nullinux.git' 'Nullinux' $one
cloneProject 'https://github.com/maK-/parameth.git' 'Parameth' $one
echo "\nSetup Parameth\n"
cd "$one/Parameth" && pip install -U -r requirements.txt

cloneProject 'https://github.com/infodox/python-pty-shells.git' 'PythonPTYShells' $one
cloneProject 'https://github.com/0x00-0x00/ShellPop.git' 'ShellPop' $one
echo "\nSetup Shellpop\n"
cd "$one/ShellPop" && pip install -r requirements.txt && chmod +x setup.py && ./setup.py install

cloneProject 'https://github.com/codingo/VHostScan.git' 'VHostScan' $one
echo "\nSetup VHostScan\n"
cd "$one/VHostScan" && python3 -m pip install -r requirements.txt 2&>/dev/null
apt install python3-levenshtein
cd "$one/VHostScan" && sed -i 's/numpy==1.12.0/numpy/g' requirements.txt 1>/dev/null 2>/dev/null && sed -i 's/numpy==1.12.0/numpy/g' setup.py 1>/dev/null 2>/dev/null && sed -i 's/pandas==0.19.2/pandas/g' requirements.txt 1>/dev/null 2>/dev/null && sed -i 's/pandas==0.19.2/pandas/g' setup.py 1>/dev/null 2>/dev/null && pip3 --no-cache-dir install -r requirements.txt

cloneProject 'https://github.com/vulnersCom/nmap-vulners.git' 'Vulners' $one
echo "\nCopy vulners to nmap scripts location \n"
cp "$one/Vulners/vulners.nse" /usr/share/nmap/scripts/vulners.nse

cloneProject 'https://github.com/vulnersCom/getsploit.git' 'Getsploit' $one
echo "\nSetup Getsploit\n"
cd "$one/Getsploit" && chmod +x setup.py && ./setup.py install

cloneProject 'https://github.com/rezasp/joomscan.git' 'Joomscan' $two
cloneProject 'https://github.com/rastating/joomlavs.git' 'JoomVS' $two
cloneProject 'https://github.com/wpscanteam/wpscan-v3.git' 'WPScan' $two
cloneProject 'https://github.com/droope/droopescan.git' 'Droopescan' $two
cloneProject 'https://github.com/rewardone/OSCPRepo.git' 'OSCPRepo' $three
echo "\nSetup OSCPRepo \n"
pip install colorama
rm -rf /root/scripts/*
cp -r /root/Documents/OSCPRepo/scripts /root/
cp -r /root/Documents/OSCPRepo/lists /root/

#Local Enumerators. Can probably take out of OSCPRepo...
direc="/root/Documents/Local Info Enum"
mkdir $direc 2>/dev/null
four="/root/Documents/Local Info Enum/Linux"
mkdir $four 2>/dev/null
five="/root/Documents/Local Info Enum/Windows"
mkdir $five 2>/dev/null
#ensure directories are created before pulling into them
sleep 1

cloneProject 'https://github.com/rebootuser/LinEnum.git' 'RebootLinEnum' $four
cloneProject 'https://github.com/dafthack/HostRecon.git' 'HostRecon' $five
cloneProject 'https://github.com/threatexpress/red-team-scripts.git' 'HostEnum' $five
cloneProject 'https://github.com/azmatt/windowsEnum' 'WindowsEnum' $five

echo "\nCopy Personal LinEnum\n"
direc="/root/Documents/Local Info Enum/Linux/"
cp "/root/Documents/OSCPRepo/Local Info Enum/LinEnum.sh" $direc

##TODO copy seatbelt and windows binaries

#Priv Esc Checkers. Can probably take out of OSCPRepo...
direc="/root/Documents/Priv Esc Checks"
mkdir $direc 2>/dev/null
six="/root/Documents/Priv Esc Checks/Linux"
mkdir $six 2>/dev/null
seven="/root/Documents/Priv Esc Checks/Windows"
mkdir $seven 2>/dev/null
#ensure directories are created before pulling into them
sleep 1

cloneProject 'https://github.com/mzet-/linux-exploit-suggester.git' 'linux-exploit-suggester' $six
cloneProject 'https://github.com/jondonas/linux-exploit-suggester-2.git' 'perl-linux-exploit-suggester' $six
cloneProject 'https://github.com/rasta-mouse/Sherlock.git' 'Sherlock' $seven


mkdir /root/Documents/Exploits 2>/dev/null
echo "\nCloning SecWiki-Windows-Kernel-Exploits\n"
direc=/root/Documents/Exploits/SecWiki-Windows-Kernel-Exploits
if [ -d "$direc" ]; then cd $direc && git pull; else git clone https://github.com/SecWiki/windows-kernel-exploits.git $direc; fi
cp -r $direc/win-exp-suggester /root/Documents/Priv\ Esc\ Checks/Windows/


echo "\nDownloading additional lists: secLists fuzzdb naughtystrings payloadallthethings probable-wordlists\n"
webDirec=/root/lists/Web
mkdir -p $webDirec 2>/dev/null 

eight='/root/lists'
mkdir -p $eight 2>/dev/null 
cloneProject 'https://github.com/danielmiessler/SecLists.git' 'secLists' $eight 
ln -s "$eight/secLists/Discovery/Web-Content" $webDirec
cloneProject 'https://github.com/fuzzdb-project/fuzzdb.git' 'fuzzdb' $eight
cloneProject 'https://github.com/minimaxir/big-list-of-naughty-strings.git' 'naughty' $eight
cloneProject 'https://github.com/swisskyrepo/PayloadsAllTheThings.git' 'payloadsAllTheThings' $eight

nine='/riit/lists/Password'
mkdir -p $nine 2>/dev/null
cloneProject 'https://github.com/berzerk0/Probable-Wordlists.git' 'probableWordlists' $nine
cloneProject 'https://github.com/initstring/passphrase-wordlist.git' 'passphrases' $nine

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
if [ ! -d "$direc" ]; then mkdir $direc; fi

echo "\nSetup Sparta for use with reconscan \n"
mv /usr/share/sparta/app/settings.py /usr/share/sparta/app/settings_orig.py
mv /usr/share/sparta/controller/controller.py /usr/share/sparta/controller/controller_orig.py
mv /etc/sparta.conf /etc/sparta_orig.conf
cp /root/Documents/OSCPRepo/scripts/random/Sparta/settings.py /usr/share/sparta/app/settings.py
cp /root/Documents/OSCPRepo/scripts/random/Sparta/controller.py /usr/share/sparta/controller/controller.py
cp /root/Documents/OSCPRepo/scripts/random/Sparta/sparta.conf /etc/sparta.conf

echo "\n ### DONE ### \n"
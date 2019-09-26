#!/bin/bash

# TODO: Covenant and other C2
# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)
# TODO: other binary setups (empire/etc)
# TODO: grab other dotfiles and zsh + oh-my-zsh

# Build dev-build environment
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade 
apt install git live-build cdebootstrap devscripts -y
git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git /root/live-build-config
cd /root/live-build-config/kali-config

# Overwrite default kali package list at kali-config/variant-default/package-lists/kali.list.chroot
# with your desired packages. See https://tools.kali.org/kali-metapackages for list of the breakdowns
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/kali.list.chroot" -O /root/live-build-config/kali-config/variant-default/package-lists/kali.list.chroot

# Ensure atom can be grabbed by apt:
wget -qO - https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -

# download things that apt can't
mkdir -p /tmp/tools/
git clone https://github.com/dirkjanm/ldapdomaindump.git /tmp/tools/ldapdomaindump
odat=`curl https://github.com/quentinhardy/odat/releases/latest -L --max-redirs 1 | grep -i "quentinhardy/odat/releases/download" | grep "x86_64" | cut -d '"' -f 2`
wget http://github.com$odat -O ~/tmp/odat.zip
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Tools"
mkdir -p $direc 
unzip ~/tmp/odat.zip -d $direc/ODAT && rm ~/tmp/odat.zip
cd $direc/ODAT && mv odat*/* .
git clone https://github.com/maK-/parameth.git $direc/parameth
git clone https://github.com/EmpireProject/Empire.git $direc/empire

# Now download everything 
# Reference: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# These packages are in /var/cache/apt/archives/
# fail safe way of downloading everything for local install is to use 'apt-get download':
for i in $(cat /root/live-build-config/kali-config/variant-default/package-lists/kali.list.chroot); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; done

# Now place in packages.chroot 
cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

# Download non-binary packages for use 
git clone https://github.com/rewardone/OSCPRepo.git /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo
git clone https://github.com/infodox/python-pty-shells.git /root/live-build-config/kali-config/common/includes.chroot/root/Documents/python-pty-shells

# Local Info Enum - Linux 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Local Info Enum"
mkdir -p $direc 2>/dev/null
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Local Info Enum/Linux"
git clone https://github.com/rebootuser/LinEnum.git $direc/RebootLinEnum
cp "/root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/Local Info Enum/LinEnum.sh" $direc/LinEnum
mkdir -p $direc 2>/dev/null

# Local Info Enum - Windows 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Local Info Enum/Windows"
mkdir -p $direc 2>/dev/null
git clone https://github.com/dafthack/HostRecon.git $direc/HostRecon
git clone https://github.com/threatexpress/red-team-scripts.git $direc/HostEnum
git clone https://github.com/azmatt/windowsEnum $direc/WinEnum

# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)

# Priv Esc Checkers - Linux
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Priv Esc Checks/Linux"
mkdir -p $direc 2>/dev/null
git clone https://github.com/mzet-/linux-exploit-suggester.git $direc/linux-exploit-suggester
git clone https://github.com/jondonas/linux-exploit-suggester-2.git $direc/perl-linux-exploit-suggester

# Priv Esc Checkers - Windows
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Priv Esc Checks/Windows"
mkdir -p $direc 2>/dev/null
git clone https://github.com/rasta-mouse/Sherlock.git $direc/Sherlock

# Pre-Compiled Exploits - Windows
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Exploits/Windows"
mkdir -p $direc
git clone https://github.com/SecWiki/windows-kernel-exploits.git $direc/SecWiki-Kernel-Exploits

# Move non-binary packages into place 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/scripts"
mkdir -p $direc
cp -r /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/scripts $direc
direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
mkdir -p $direc
cp -r /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/lists $direc

webDirec="/root/live-build-config/kali-config/common/includes.chroot/root/lists/Web"
direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
git clone https://github.com/danielmiessler/SecLists.git $direc/secLists
ln -s $direc/secLists/Discovery/Web-Content $webDirec
git clone https://github.com/fuzzdb-project/fuzzdb.git $direc/fuzzdb
git clone https://github.com/minimaxir/big-list-of-naughty-strings.git $direc/naughty
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git $direc/payloadAllTheThings

mkdir -p $direc/Password 
git clone https://github.com/berzerk0/Probable-Wordlists.git $direc/Password/probablyWordlists
git clone https://github.com/initstring/passphrase-wordlist.git $direc/Password/passphrases

# Force the install to use a custom preseed.cfg 
cat << EOF > /root/live-build-config/kali-config/common/includes.binary/isolinux/install.cfg
label install
    menu label ^Install Automated
    linux /install/vmlinuz
    initrd /install/initrd.gz
    append vga=788 -- quiet file=/cdrom/install/preseed.cfg locale=en_US keymap=us hostname=kali domain=local.lan
EOF

# Have the SSH service start by default. To do this, we can use a chroot hook script 
# which is placed in the “hooks” directory:
echo 'systemctl enable ssh' >  /root/live-build-config/kali-config/common/hooks/01-start-ssh.chroot
chmod +x /root/live-build-config/kali-config/common/hooks/01-start-ssh.chroot

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/preseed.cfg" -O /root/live-build-config/kali-config/common/includes.installer/preseed.cfg

#questions that still require answer:
#install grub boot loader, /dev/sda, lots of bugs, find a workaround that works

# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 
# Once completed, your ISO can be found in the live-build root directory.
/root/live-build-config/./build.sh -v
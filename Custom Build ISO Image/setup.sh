#!/bin/bash

# TODO: Covenant and other C2
# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)
# TODO: other binary setups (empire/etc)
# TODO: grab other dotfiles and zsh + oh-my-zsh

# Build dev-build environment
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade 
apt install git live-build cdebootstrap devscripts -y
direc="/root/live-build-config"
if [ -d $direct ]; then cd $direc && git pull; else git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git $direc; fi
cd "$direc/kali-config"

# Overwrite default kali package list at kali-config/variant-default/package-lists/kali.list.chroot
# with your desired packages. See https://tools.kali.org/kali-metapackages for list of the breakdowns
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/kali.list.chroot" -O /root/live-build-config/kali-config/variant-default/package-lists/kali.list.chroot

# Ensure atom can be grabbed by apt:
wget -qO - https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -

# download things that apt can't
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Tools"
mkdir -p $direc 2>/dev/null
if [ -d "$direc/parameth" ]; then cd "$direc/parameth" && git pull; else git clone https://github.com/maK-/parameth.git "$direc/parameth"; fi

# Now download everything 
# Reference: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# These packages are in /var/cache/apt/archives/
# fail safe way of downloading everything for local install is to use 'apt-get download':
cd /var/cache/apt/archives/
for i in $(cat /root/live-build-config/kali-config/variant-default/package-lists/kali.list.chroot); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; apt-get download $i; done

# Now place in packages.chroot 
cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

# Download non-binary packages for use 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Documents"
mkdir -p $direc 2>/dev/null
if [ -d "$direc/OSCPRepo" ]; then cd "$direc/OSCPRepo" && git pull; else git clone https://github.com/rewardone/OSCPRepo.git "$direc/OSCPRepo"; fi
if [ -d "$direc/python-pty-shells" ]; then cd "$direc/python-pty-shells" && git pull; else git clone https://github.com/infodox/python-pty-shells.git "$direc/python-pty-shells"; fi

# Local Info Enum - Linux 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Local_Info_Enum"
mkdir -p "$direc/Linux" 2>/dev/null
if [ -d "$direc/Linux/RebootLinEnum" ]; then cd "$direc/Linux/RebootLinEnum" && git pull; else git clone https://github.com/rebootuser/LinEnum.git "$direc/Linux/RebootLinEnum"; fi
cp /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/Local\ Info\ Enum/LinEnum.sh "$direc/Linux/LinEnum.sh"

# Local Info Enum - Windows 
mkdir -p "$direc/Windows" 2>/dev/null
if [ -d "$direc/Windows/HostRecon" ]; then cd "$direc/Windows/HostRecon" && git pull; else git clone https://github.com/dafthack/HostRecon.git "$direc/Windows/HostRecon"; fi
if [ -d "$direc/Windows/HostEnum" ]; then cd "$direc/Windows/HostEnum" && git pull; else git clone https://github.com/threatexpress/red-team-scripts.git "$direc/Windows/HostEnum"; fi
if [ -d "$direc/WinEnum" ]; then cd "$direc/WinEnum" && git pull; else git clone https://github.com/azmatt/windowsEnum "$direc/WinEnum"; fi

# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)

# Priv Esc Checkers - Linux
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Priv_Esc_Checks"
mkdir -p "$direc/Linux" 2>/dev/null
if [ -d "$direc/Linux/linux-exploit-suggester" ]; then cd "$direc/Linux/linux-exploit-suggester" && git pull; else git clone https://github.com/mzet-/linux-exploit-suggester.git "$direc/Linux/linux-exploit-suggester"; fi
if [ -d "$direc/Linux/perl-linux-exploit-suggester" ]; then cd "$direc/Linux/perl-linux-exploit-suggester" && git pull; else git clone https://github.com/jondonas/linux-exploit-suggester-2.git "$direc/Linux/perl-linux-exploit-suggester"; fi

# Priv Esc Checkers - Windows
mkdir -p "$direc/Windows" 2>/dev/null
if [ -d "$direc/Windows/Sherlock" ]; then cd "$direc/Windows/Sherlock" && git pull; else git clone https://github.com/rasta-mouse/Sherlock.git "$direc/Windows/Sherlock"; fi

# Pre-Compiled Exploits - Windows
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Exploits/Windows"
mkdir -p $direc
if [ -d "$direc/secWiki-Kernel-Exploits" ]; then cd "$direc/secWiki-Kernel-Exploits" && git pull; else git clone https://github.com/SecWiki/windows-kernel-exploits.git "$direc/secWiki-Kernel-Exploits"; fi

# Move non-binary packages into place 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/scripts"
mkdir -p $direc
cp -r /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/scripts $direc
direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
mkdir -p $direc
cp -r /root/live-build-config/kali-config/common/includes.chroot/root/Documents/OSCPRepo/lists $direc

webDirec="/root/live-build-config/kali-config/common/includes.chroot/root/lists/Web"
direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
if [ -d "$direc/secLists" ]; then cd "$direc/secLists" && git pull; else git clone https://github.com/danielmiessler/SecLists.git "$direc/secLists"; fi
ln -s $direc/secLists/Discovery/Web-Content $webDirec
if [ -d "$direc/fuzzdb" ]; then cd "$direc/fuzzdb" && git pull; else git clone https://github.com/fuzzdb-project/fuzzdb.git "$direc/fuzzdb"; fi
if [ -d "$direc/naughty" ]; then cd "$direc/naughty" && git pull; else git clone https://github.com/minimaxir/big-list-of-naughty-strings.git "$direc/naughty"; fi
if [ -d "$direc/payloadAllTheThings" ]; then cd "$direc/payloadAllTheThings" && git pull; else git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git "$direc/payloadAllTheThings"; fi

mkdir -p "$direc/Password"
if [ -d "$direc/Password/probableWordlists" ]; then cd "$direc/Password/probableWordlists" && git pull; else git clone https://github.com/berzerk0/Probable-Wordlists.git "$direc/Password/probableWordlists"; fi
if [ -d "$direc/Password/passphrases" ]; then cd "$direc/Password/passphrases" && git pull; else git clone https://github.com/initstring/passphrase-wordlist.git "$direc/Password/passphrases"; fi


direc="/root/live-build-config/kali-config/common/includes.chroot/usr/share/dotdotpwn/Reports"
if [ ! -d $direc ]; then mkdir $direc; fi


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

# Have PostgreSQL start by default for metasploit. 
echo 'systemctl enable postgresql' > /root/live-build-config/kali-config/common/hooks/02-start-postgresql.chroot
chmod +x /root/live-build-config/kali-config/common/hooks/02-start-postgresql.chroot 

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/preseed.cfg" -O /root/live-build-config/kali-config/common/includes.installer/preseed.cfg

#questions that still require answer:
#install grub boot loader, /dev/sda, lots of bugs, find a workaround that works

# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 
# Once completed, your ISO can be found in the live-build root directory.
#/root/live-build-config/./build.sh -v
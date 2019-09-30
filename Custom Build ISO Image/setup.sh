#!/bin/bash

# TODO: Covenant and other C2
# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)
# TODO: grab other dotfiles and zsh + oh-my-zsh

# Build dev-build environment
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade 
apt install git live-build cdebootstrap devscripts -y
direc="/root/live-build-config"
if [ -d $direct ]; then cd $direc && git pull; else git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git $direc; fi
cd "$direc/kali-config"

vardefault="/root/live-build-config/kali-config/variant-default/package-lists"
varlxde="/root/live-build-config/kali-config/variant-lxde/package-lists"
varxfce="/root/live-build-config/kali-config/variant-xfce/package-lists"

# Overwrite default kali package list at kali-config/variant-default/package-lists/kali.list.chroot
# with your desired packages. See https://tools.kali.org/kali-metapackages for list of the breakdowns
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/kali.list.chroot" -O "$vardefault/kali.list.chroot"
#cp "$vardefault/kali.list.chroot" "$varlxde/kali.list.chroot"
#cp "$vardefault/kali.list.chroot" "$varxfce/kali.list.chroot"

# Download packages to include on CD if desired
# Reference: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# fail safe way of downloading everything for local install is to use 'apt-get download':
#cd /var/cache/apt/archives/ && rm -rf /var/cache/apt/archives/*.deb
#for i in $(cat "$vardefault/kali.list.chroot"); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; apt-get download $i 2>/dev/null; done

# Now place in packages.chroot 
#cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

# Download non-binary packages for use 
direc="/root/live-build-config/kali-config/common/includes.chroot/opt"
mkdir -p $direc 2>/dev/null
if [ -d "$direc/parameth" ]; then cd "$direc/parameth" && git pull; else git clone https://github.com/maK-/parameth.git "$direc/parameth"; fi
if [ -d "$direc/vulners" ]; then cd "$direc/vulners" && git pull; else git clone https://github.com/vulnersCom/nmap-vulners.git "$direc/vulners"; fi
if [ -d "$direc/python-pty-shells" ]; then cd "$direc/python-pty-shells" && git pull; else git clone https://github.com/infodox/python-pty-shells.git "$direc/python-pty-shells"; fi

direc="/root/live-build-config/kali-config/common/includes.chroot/root/Documents"
mkdir -p "$direc/OSCPRepo"
if [ -d "/tmp/OSCPRepo" ]; then cd "/tmp/OSCPRepo" && git pull; else git clone https://github.com/rewardone/OSCPRepo.git "/tmp/OSCPRepo"; fi
cp -r /tmp/OSCPRepo/KeepNotes "$direc/OSCPRepo/KeepNotes"

direc="/root/live-build-config/kali-config/common/includes.chroot/root/scripts"
mkdir -p $direc
cp -r /tmp/OSCPRepo/scripts $direc 

direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
mkdir -p $direc
cp -r /tmp/OSCPRepo/lists $direc


# Local Info Enum - Linux 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Local_Info_Enum"
mkdir -p "$direc/Linux" 2>/dev/null
if [ -d "$direc/Linux/RebootLinEnum" ]; then cd "$direc/Linux/RebootLinEnum" && git pull; else git clone https://github.com/rebootuser/LinEnum.git "$direc/Linux/RebootLinEnum"; fi


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


# Download and move lists 
# seclists is a package in kali-rolling, TODO hook for symlink
webDirec="/root/live-build-config/kali-config/common/includes.chroot/root/lists/Web"
direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
#if [ -d "$direc/secLists" ]; then cd "$direc/secLists" && git pull; else git clone https://github.com/danielmiessler/SecLists.git "$direc/secLists"; fi
#ln -s $direc/secLists/Discovery/Web-Content $webDirec
if [ -d "$direc/fuzzdb" ]; then cd "$direc/fuzzdb" && git pull; else git clone https://github.com/fuzzdb-project/fuzzdb.git "$direc/fuzzdb"; fi
if [ -d "$direc/naughty" ]; then cd "$direc/naughty" && git pull; else git clone https://github.com/minimaxir/big-list-of-naughty-strings.git "$direc/naughty"; fi
if [ -d "$direc/payloadAllTheThings" ]; then cd "$direc/payloadAllTheThings" && git pull; else git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git "$direc/payloadAllTheThings"; fi

mkdir -p "$direc/Password"
if [ -d "$direc/Password/probableWordlists" ]; then cd "$direc/Password/probableWordlists" && git pull; else git clone https://github.com/berzerk0/Probable-Wordlists.git "$direc/Password/probableWordlists"; fi
if [ -d "$direc/Password/passphrases" ]; then cd "$direc/Password/passphrases" && git pull; else git clone https://github.com/initstring/passphrase-wordlist.git "$direc/Password/passphrases"; fi

direc="/root/live-build-config/kali-config/common/includes.chroot/usr/share/dotdotpwn/Reports"
if [ ! -d $direc ]; then mkdir -p $direc; fi

# Force the install to use a custom preseed.cfg 
cat << EOF > /root/live-build-config/kali-config/common/includes.binary/isolinux/install.cfg
label install
    menu label ^Install Automated
    linux /install/vmlinuz
    initrd /install/initrd.gz
    append vga=788 -- quiet file=/cdrom/install/preseed.cfg locale=en_US keymap=us hostname=kali domain=local.lan
EOF

direc="/root/live-build-config/kali-config/common/hooks/normal"
mkdir -p $direc
# Have the SSH service start by default. To do this, we can use a chroot hook script 
# which is placed in the “hooks/normal” directory:
cat << EOF > "$direc/01-start-ssh.chroot"
#!/bin/bash
systemctl enable ssh;
systemctl start ssh;
EOF

# Have PostgreSQL start by default for metasploit. 
cat << EOF > "$direc/02-start-postgresql.chroot"
#!/bin/bash
systemctl enable postgresql;
systemctl start postgresql;
EOF

# Add and install atom
cat << EOF > "$direc/50-install-atom.chroot"
#!/bin/bash
wget -qO - https://packagecloud.io/AtomEditor/atom/gpgkey | sudo apt-key add -
apt-get update
apt-get install atom
EOF

# Add i386 and wine32
cat << EOF > "$direc/51-add-arch-i386-wine32.chroot"
#!/bin/bash
#Needed for shellter, veil, and others
dpkg --add-architecture i386 && apt-get update && apt-get install wine32
EOF

# Update pip 
cat << EOF > "$direc/100-pip.chroot"
#!/bin/bash
pip3 install --upgrade pip
EOF

# pip install parameth requirements
cat << EOF > "$direc/101-pip-parameth.chroot"
#!/bin/bash
pip3 install -r /opt/parameth/requirements.txt
EOF

# Disable 'Press Enter to start' for dotdotpwn
cat << EOF > "$dorec/150-dotdotpwn.chroot"
#!/bin/bash
sed -e "s/<STDIN>;/#<STDIN>;/" /usr/share/dotdotpwn/dotdotpwn.pl > /tmp/dotdotpwn.pl 
mv /tmp/dotdotpwn.pl /usr/share/dotdotpwn/dotdotpwn.pl
chmod +x /usr/share/dotdotpwn/dotdotpwn.pl
EOF

# update searchsploit db
cat << EOF > "$direc/200-searchsploit.chroot"
#!/bin/bash
searchsploit -u
EOF

# update nmap scripts
cat << EOF > "$direc/201-nmap.chroot"
#!/bin/bash
nmap --script-updatedb
EOF

# make hooks executable
chmod +x "$direc/*.chroot"

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
wget "https://raw.githubusercontent.com/rewardone/OSCPRepo/master/Custom Build ISO Image/preseed.cfg" -O /root/live-build-config/kali-config/common/includes.installer/preseed.cfg

# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 
# Once completed, your ISO can be found in the live-build root directory.
#/root/live-build-config/./build.sh --distribution kali-rolling --variant default --verbose
#/root/live-build-config/./build.sh --distribution kali-rolling --variant lxde --verbose
#/root/live-build-config/./build.sh --distribution kali-rolling --variant xfce --verbose
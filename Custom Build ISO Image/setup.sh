#!/bin/bash

# TODO: Covenant and other C2
# TODO: binaries for Seatbelt and other enumerators (ie, no sherlock)

# Build dev-build environment
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade 
apt install git live-build cdebootstrap devscripts -y
direc="/root/live-build-config"
if [ -d $direct ]; then cd $direc && git pull; else git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git $direc; fi
cd "$direc/kali-config"

# we need the files in the custom iso image directory
if [ -d "/tmp/OSCPRepo" ]; then cd "/tmp/OSCPRepo" && git pull; else git clone https://github.com/rewardone/OSCPRepo.git "/tmp/OSCPRepo"; fi

vardefault="/root/live-build-config/kali-config/variant-default/package-lists"
varlxde="/root/live-build-config/kali-config/variant-lxde/package-lists"
varxfce="/root/live-build-config/kali-config/variant-xfce/package-lists"

# Overwrite default kali package list at kali-config/variant-default/package-lists/kali.list.chroot
# with your desired packages. See https://tools.kali.org/kali-metapackages for list of the breakdowns
cp "/tmp/Custom Build ISO Image/kali.list.chroot" "$vardefault/kali.list.chroot"
#cp "$vardefault/kali.list.chroot" "$varlxde/kali.list.chroot"
#cp "$vardefault/kali.list.chroot" "$varxfce/kali.list.chroot"

# check if any packages have been removed from kali-rolling before continuing
REM=""
for i in $(cat "$vardefault/kali.list.chroot"); do res=""; res=$(apt-cache search $i); if [ -z "${res}" ]; then echo "$i has been removed from kali-rolling"; REM="$i $REM"; fi; done
if [ ! -z "${REM}" ]; then exit 1; fi;

# Download packages to include on CD if desired
# Reference: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# fail safe way of downloading everything for local install is to use 'apt-get download':
#apt clean
#for i in $(cat "$vardefault/kali.list.chroot"); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; apt-get download $i 2>/dev/null; done

# Now place in packages.chroot 
#cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

# Download non-binary packages for use 
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Documents"
mkdir -p "$direc/OSCPRepo"
cp -r /tmp/OSCPRepo/KeepNotes "$direc/OSCPRepo/KeepNotes"

direc="/root/live-build-config/kali-config/common/includes.chroot/root/scripts"
mkdir -p $direc
cp -r /tmp/OSCPRepo/scripts $direc 

direc="/root/live-build-config/kali-config/common/includes.chroot/root/lists"
mkdir -p $direc
cp -r /tmp/OSCPRepo/lists $direc

# Force the install to use a custom preseed.cfg 
cat << EOF > /root/live-build-config/kali-config/common/includes.binary/isolinux/install.cfg
label install
    menu label ^Install Automated
    linux /install/vmlinuz
    initrd /install/initrd.gz
    append vga=788 -- quiet file=/cdrom/install/preseed.cfg locale=en_US.UTF-8 keymap=us hostname=kali domain=local.lan
EOF

# automatically choose our label 'install' that we just created 
cat << EOF > /usr/share/live/build/bootloaders/isolinux/isolinux.cfg
include menu.cfg
default install
prompt 0
timeout 0
EOF

# copy all hooks and make hooks executable
direc="/root/live-build-config/kali-config/common/hooks/normal"
mkdir -p $direc
cp -R "tmp/OSCPRepo/Custom Build ISO Image/hooks/" $direc/
chmod +x "$direc/*.chroot"

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
cp "tmp/OSCPRepo/Custom Build ISO Image/preseed.cfg" /root/live-build-config/kali-config/common/includes.installer/preseed.cfg

# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 
# Once completed, your ISO can be found in the live-build root directory.
/root/live-build-config/./build.sh --distribution kali-rolling --variant default --verbose
#/root/live-build-config/./build.sh --distribution kali-rolling --variant lxde --verbose
#/root/live-build-config/./build.sh --distribution kali-rolling --variant xfce --verbose
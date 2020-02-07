#!/bin/bash

# TODO: Covenant, Merlin, and other C2
# TODO: pre-built binaries for Seatbelt and other enumerators (ie, no sherlock)
# TODO: Experimenting with "installer" only, set in build.sh "TYPE"
#     also requires apt install debian-cd simple-cdd xorriso
#     echo "http://http.kali.org/" > /root/live-build-config/.mirror
#	fix python (/usr/lib/python3/dist-packages/simple_cdd/tools/mirror_download.py):
#	This is due to http.kali.org not allowing the urlretrieve user agent and no easy way to add a user
#	agent header to urlretrieve()
#		apply python UA download patch:
#		import urllib
#		import shutil
#		:55 (after log.debug)...remove request.urlretrieve(url, filename=output)
#		download_req = request.Request(url,headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0'})
#		with urllib.request.urlopen(download_req) as response, open(output, 'wb') as out_file:
#			shutil.copyfileobj(response, out_file)
#		out_file.close()
# If apt is still prompting (due to hooks or otherwise), add this to /etc/apt/apt.conf.d/<your file>. APT::Get::Assume-Yes "true";
# Other flags you can add to auto/build-config: #--apt-indices, --apt-recommends, --cache-packages are true by default
#    --apt-recommends false \
#    --apt-indices false \
#    --clean \ 
#    --debian-installer-gui false \
#    --cache-packages true \ 

# Build dev-build environment
echo
echo "=============================================================================="
echo "Updating and upgrading installation"
echo "=============================================================================="
echo
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade 

echo
echo "=============================================================================="
echo "Downloading and updating live-build-config repo"
echo "=============================================================================="
echo
apt install git live-build cdebootstrap devscripts -y
direc="/root/live-build-config"
if [ -d $direc ]; then cd $direc && git pull; else git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git $direc; fi
cd "$direc/kali-config"

echo
echo "=============================================================================="
echo "Downloading live-build-configuration files from OSCPRepo"
echo "=============================================================================="
echo
# we need the files in the custom iso image directory
#if [ -d "/tmp/OSCPRepo" ]; then cd "/tmp/OSCPRepo" && git pull; else git clone https://github.com/rewardone/OSCPRepo.git "/tmp/OSCPRepo"; fi

vargnome="/root/live-build-config/kali-config/variant-gnome/package-lists"
varlxde="/root/live-build-config/kali-config/variant-lxde/package-lists"
varxfce="/root/live-build-config/kali-config/variant-xfce/package-lists"

# Overwrite default kali package list at kali-config/variant-default/package-lists/kali.list.chroot
# with your desired packages. See https://tools.kali.org/kali-metapackages for list of the breakdowns
# Make sure lxde and xfce have their own package lists to include their specific desktop environments
cp "/tmp/OSCPRepo/Custom Build ISO Image/gnome/kali.list.chroot" "$vargnome/kali.list.chroot"
cp "/tmp/OSCPRepo/Custom Build ISO Image/lxde/kali.list.chroot" "$varlxde/kali.list.chroot"
cp "/tmp/OSCPRepo/Custom Build ISO Image/xfce/kali.list.chroot" "$varxfce/kali.list.chroot"

echo
echo "=============================================================================="
echo "Checking for packages that may have been removed from kali-rolling"
echo "=============================================================================="
echo
# check if any packages have been removed from kali-rolling before continuing
# check in each build list. These can be commented out if not building all three
#REM=""
#for i in $(cat "$vargnome/kali.list.chroot" | grep -v "#" | grep -ve "^$"); do res=""; res=$(apt-cache search $i); if [ -z "${res}" ]; then echo "$i has been removed from kali-rolling. Make a hook or download and add the package manually!"; REM="$i $REM"; fi; done
#if [ ! -z "${REM}" ]; then exit 1; fi;

#REM=""
#for i in $(cat "$varlxde/kali.list.chroot" | grep -v "#" | grep -ve "^$"); do res=""; res=$(apt-cache search $i); if [ -z "${res}" ]; then echo "$i has been removed from kali-rolling. Make a hook or download and add the package manually!"; REM="$i $REM"; fi; done
#if [ ! -z "${REM}" ]; then exit 1; fi;

REM=""
for i in $(cat "$varxfce/kali.list.chroot" | grep -v "#" | grep -ve "^$"); do res=""; res=$(apt-cache search $i); if [ -z "${res}" ]; then echo "$i has been removed from kali-rolling. Make a hook or download and add the package manually!"; REM="$i $REM"; fi; done
if [ ! -z "${REM}" ]; then exit 1; fi;

# Download packages to include on locally on the CD if desired
# Reference: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# fail safe way of downloading everything for local install is to use 'apt-get download':
#apt clean
#for i in $(cat "$vardefault/kali.list.chroot"); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; apt-get download $i 2>/dev/null; done

# Now place the local packages in packages.chroot 
#cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

echo
echo "=============================================================================="
echo "Moving notes, scripts, and lists for local inclusion"
echo "=============================================================================="
echo
# Copy OSCP Repo notes into chroot Documents
direc="/root/live-build-config/kali-config/common/includes.chroot/root/Documents"
mkdir -p "$direc/OSCPRepo"
cp -r /tmp/OSCPRepo/KeepNotes "$direc/OSCPRepo/KeepNotes"
# Issues with training/blogs for some reason, so remove it 
rm -rf /root/live-build-config/config/includes.chroot/root/Documents/OSCPRepo/KeepNotes/KeepNotes/BookmarkList/training-research-news/
rm -rf /root/live-build-config/config/includes.chroot/root/Documents/OSCPRepo/KeepNotes/BookmarkList/training-research-news/

# Copy OSCP Repo scripts into chroot scripts
direc="/root/live-build-config/kali-config/common/includes.chroot/root/scripts"
mkdir -p $direc
cp -r /tmp/OSCPRepo/scripts $direc 

# Copy OSCP Repo lists into chroot lists. Zipping first to save space.
direc="/root/live-build-config/kali-config/common/includes.chroot/usr/share/lists/OSCPRepo"
mkdir -p $direc
tar -zcf /tmp/OSCPRepo_lists.tar.gz /tmp/OSCPRepo/lists/*
cp /tmp/OSCPRepo_lists.tar.gz $direc
rm /tmp/OSCPRepo_lists.tar.gz

echo
echo "=============================================================================="
echo "Preseed and install.cfg"
echo "=============================================================================="
echo

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
cp "/tmp/OSCPRepo/Custom Build ISO Image/preseed.cfg" /root/live-build-config/kali-config/common/includes.installer/preseed.cfg

# Force the install to use the custom preseed.cfg 
cat << EOF > /root/live-build-config/kali-config/common/includes.binary/isolinux/install.cfg
label install
    menu label ^Install Automated
    linux /install/vmlinuz
    initrd /install/initrd.gz
    append vga=788 -- quiet file=/cdrom/install/preseed.cfg locale=en_US.UTF-8 keymap=us hostname=kali domain=local.lan
EOF

echo
echo "=============================================================================="
echo "Editing isolinux to auto select our configuration for install by default"
echo "=============================================================================="
echo
# automatically choose our label 'install' that we just created 
cat << EOF > /usr/share/live/build/bootloaders/isolinux/isolinux.cfg
include menu.cfg
default install
prompt 0
timeout 0
EOF

echo
echo "=============================================================================="
echo "Copying custom hooks"
echo "=============================================================================="
echo
# copy all hooks and make hooks executable
direc="/root/live-build-config/kali-config/common/hooks/normal"
mkdir -p $direc
rm -rf $direc/*
rsync -r "/tmp/OSCPRepo/Custom Build ISO Image/hooks/" $direc
chmod +x $direc/*.chroot


echo
echo "=============================================================================="
echo "Modifying build options in auto/config"
echo "=============================================================================="
echo
# adding two options, --apt-recommends false and --debian-installer-gui false
#sed -i 's/--distribution "$dist" \\\n        --debian-installer-distribution "$dist" \\/--distribution "$dist" \\\n        --apt-recommends false \\\n        --debian-installer-gui false \\\n        --debian-installer-distribution "$dist" \\/g' /root/live-build-config/auto/config

echo
echo "=============================================================================="
echo "Building....this will take some time..."
echo "=============================================================================="
echo
# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 
cd /root/
# Note that variant-default is now xfce and NOT gnome
#/root/live-build-config/./build.sh --distribution kali-rolling --variant gnome --verbose
#/root/live-build-config/./build.sh --distribution kali-rolling --variant lxde --verbose
/root/live-build-config/./build.sh --distribution kali-rolling --variant xfce --verbose

# Once completed, your ISO can be found in the live-build root directory.

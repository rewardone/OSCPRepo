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

# Build dev-build environment
# variants: xfce, gnome, lxde
live_build_dir="/root/live-build-config"
variant="xfce"
live_build_config_package_list="$live_build_dir/kali-config/variant-$variant/package-lists/kali.list.chroot"

#============TESTING============#
simple_cdd_profile_name="kali-custom"
simple_cdd_profile_folder="$live_build_dir/simple-cdd/profiles/$simple_cdd_profile_name"
simple_cdd_profile_package_list="$simple_cdd_profile_filder/$simple_cdd_profile_name.packages"
simple_cdd_conf="$live_build_dir/simple-cdd/simple-cdd.conf"
#============TESTING============#

echo
echo "=============================================================================="
echo "Updating and upgrading installation and headers"
echo "=============================================================================="
echo
apt-get update && apt-get -y upgrade && apt-get -y dist-upgrade
apt-get -y install linux-headers-$(uname-r)

echo
echo "=============================================================================="
echo "Downloading and updating live-build-config repo"
echo "=============================================================================="
echo

# git, curl, live-build, cdebootstrap, and devscripts for live build. rsync for this script. TODO, remove rsync dependency.
apt install git curl rsync live-build cdebootstrap devscripts -y
direc=$live_build_dir
if [ -d $direc ]; then cd $direc && git pull; else git clone https://gitlab.com/kalilinux/build-scripts/live-build-config.git $direc; fi


# If you're going to be running multiple builds, a squid could be useful 
# Give option to [Y/N]
# https://github.com/prateepd/kali-live-build/blob/master/squid.conf
# Squid will be installed and started on 3128
#echo
#echo "=============================================================================="
#echo "Setting up squid"
#echo "=============================================================================="
#echo
#
# apt-get install squid
# cat << EOF > /etc/squid/squid.conf
#acl localnet src 192.168.0.0/16
#acl SSL_ports port 443
#acl Safe_ports port 80
#acl Safe_ports port 443
#acl CONNECT method CONNECT
##http_access deny !Safe_ports
#http_access deny CONNECT !SSL_ports
#http_access allow localhost manager
#http_access deny manager
#http_access allow localnet
#http_access allow localhost
#http_access deny all
#http_port 3128
#cache_dir ufs /var/spool/squid 4096 16 256
#maximum_object_size 524388 KB
#coredump_dir /var/spool/squid
#refresh_pattern ^ftp:	1440	20%	10080
#refresh_pattern ^gopher:	1440	0%	1440
#refresh_pattern -i (/cgi-bin/|\?)	0	0%	0
#refresh_pattern (Release|Packages(.gz)*)$	0	20%	2880
#refresh_pattern .	0	20%	4320
# EOF
# /etc/init.d/squid start
# TODO
# Need to modify $live_build_dir/auto/config lb_opts with --apt-http-proxy=http://localhost:3128
# BUT need to ensure that this doesn't overwrite any options we want to set down later...
# maybe store them as a global var, add to it ourselves, and only do one write at the end just before we build...


echo
echo "=============================================================================="
echo "Downloading live-build and simple-cdd configuration files from OSCPRepo"
echo "=============================================================================="
echo
# we need the files in the custom iso image directory, so ensure we have OSCPRepo
if [ -d "/tmp/OSCPRepo" ]; then cd "/tmp/OSCPRepo" && git pull; else git clone https://github.com/rewardone/OSCPRepo.git "/tmp/OSCPRepo"; fi

#TODO currently only one variant at a time...
# Overwrite default kali package list at kali-config/variant-$variant/package-lists/kali.list.chroot with your desired packages
# Make sure lxde and xfce have their own package lists to include their specific desktop environments 
# This script will use the package lists in /tmp/OSCPRepo/Custom Build ISO Image/<variant>/kali.list.chroot
cp "/tmp/OSCPRepo/Custom Build ISO Image/$variant/kali.list.chroot" "$live_build_config_package_list"

#============TESTING============#
# Simple-CDD: simple-cdd/profiles/kali-custom and place in kali-custom/kali-custom.packages
# mkdir -p $simple_cdd_profile_folder
# cp "/tmp/OSCPRepo/Custom Build ISO Image/$variant/kali.list.chroot" "$simple_cdd_profile_package_list"
#
# Add our profile to simple-cdd.conf and auto_select it
# sed -i 's,#profiles="",'"profiles=\"$simple_cdd_profile_name\""',g' $simple_cdd_conf
# sed -i 's,#auto_profiles="",'"auto_profiles=\"$simple_cdd_profile_name\""',g' $simple_cdd_conf
#============TESTING============#

echo
echo "=============================================================================="
echo "Checking for packages that may have been removed from kali-rolling"
echo "=============================================================================="
echo
# check if any packages have been removed from kali-rolling before continuing
# check in each build list. These can be commented out if not building all three
REM=""
for i in $(cat "/tmp/OSCPRepo/Custom Build ISO Image/$variant/kali.list.chroot" | grep -v "#" | grep -ve "^$"); do res=""; res=$(apt-cache search $i); if [ -z "${res}" ]; then echo "$i has been removed from kali-rolling. Make a hook or download and add the package manually!"; REM="$i $REM"; fi; done
if [ ! -z "${REM}" ]; then exit 1; fi;

# Download packages to include on locally on the CD if desired
# NOTE: This is REQUIRED in default live-build configurations where the '--installer' flag is 'cdrom' in $lb_opts (auto/config)
# Reference for downloads: https://www.ostechnix.com/download-packages-dependencies-locally-ubuntu/
# --reinstall will bypass "already installed" errors, install --download-only 'should' grab dependencies as well
# fail safe way of downloading everything for local install is to use 'apt-get download':
# A mirror with apt-move or another utility could also work
#apt clean
#for i in $(cat "$vardefault/kali.list.chroot"); do for j in $(apt-cache depends $i | grep -E 'Depends|Recommends|Suggests' | cut -d ':' -f 2,3 | sed -e s/'<'/''/ -e s/'>'/''/); do apt-get download $j 2>/dev/null; done; apt-get download $i 2>/dev/null; done
#
# Now place the local packages in packages.chroot 
#cp -R /var/cache/apt/archives/*.deb /root/live-build-config/kali-config/common/packages.chroot/

echo
echo "=============================================================================="
echo "Creating custom Tasksel task"
echo "=============================================================================="
echo

# Kali wants to use tasksel now, so lets set that up, generate the hook dynamically
# NOTE: This will only work with '--installer' flag is 'live' in $lb_opts (auto/config)
# theurbanpenguin.com/creating-tasksel-custom-tasks-ubuntu-16-04/
tasksel_hook="$live_build_dir/kali-config/common/includes.installer/usr/lib/live-installer.d/0050-custom-tasksel"
tasksel_file="/target/usr/share/tasksel/descs/kali-custom.desc"
if [ ! -f "$tasksel_hook" ]; then
  cat << EOF > $tasksel_hook
#!/bin/sh
set -e
echo 'Task: kali-custom
Relevance: 1
Description: Kali-Custom Package List
 This task installs custom ISO tools as listed in kali.list.chroot
Packages: list
EOF
  for i in $(cat "/tmp/OSCPRepo/Custom Build ISO Image/$variant/kali.list.chroot"); do echo " $i" >> $tasksel_hook; done
  cat << EOF >> $tasksel_hook
Section: user' > $tasksel_file
EOF
  chmod +x $tasksel_hook
fi

echo
echo "=============================================================================="
echo "Moving notes, scripts, lists, and binaries for local inclusion"
echo "=============================================================================="
echo
# This should be handled by 99998-oscprepo.chroot hook
# # Copy OSCP Repo notes into chroot Documents
# direc="$live_build_dir/kali-config/common/includes.chroot/root/Documents"
# mkdir -p "$direc/OSCPRepo"
# cp -r /tmp/OSCPRepo/CherryTrees "$direc/OSCPRepo/CherryTrees"

# # Copy OSCP Repo scripts into chroot scripts
# direc="$live_build_dir/kali-config/common/includes.chroot/root/scripts"
# mkdir -p $direc
# cp -r /tmp/OSCPRepo/scripts $direc 

# # Copy OSCP Repo lists into chroot lists. Zipping first to save space.
# direc="$live_build_dir/kali-config/common/includes.chroot/usr/share/lists/OSCPRepo"
# mkdir -p $direc
# tar -zcf /tmp/OSCPRepo_lists.tar.gz /tmp/OSCPRepo/lists/* 2>/dev/null
# cp /tmp/OSCPRepo_lists.tar.gz $direc
# rm /tmp/OSCPRepo_lists.tar.gz

# If you've created custom windows executables that you would like to include, place them in tmp/windows-binaries
direc="$live_build_dir/kali-config/common/includes.chroot/usr/share/windows-binaries"
mkdir -p $direc
cp -r /tmp/windows-binaries/* $direc 2>/dev/null

echo
echo "=============================================================================="
echo "Preseed and install.cfg"
echo "=============================================================================="
echo

# Preseed. Some examples can be found: https://gitlab.com/kalilinux/recipes/kali-preseed-examples
# Modify it as needed and place it in: 
cp "/tmp/OSCPRepo/Custom Build ISO Image/preseed.cfg" "$live_build_dir/kali-config/common/includes.installer/preseed.cfg"

# kali documentation places preseed in debian-installer/preseed. Would need to determine the right path for isolinux
#cp "/tmp/OSCPRepo/Custom Build ISO Image/preseed.cfg" "$live_build_dir/kali-config/common/debian-installer/preseed.cfg"

# Force the install to use the custom preseed.cfg 
# this can be placed in /usr/share/live/build/bootloaders/isolinux/install.cfg
# url=http:// or file=/cdrom/
# if using includes.binary/isolinux/install.cfg: the preseed path is file=/preseed.cfg
# if using /usr/share/live/build/bootloaders/isolinux/install.cfg: the preseed path is file=???
#isolinux_install="/usr/share/live/build/bootloaders/isolinux/install.cfg"
isolinux_alternate_install="$live_build_dir/kali-config/common/includes.binary/isolinux/install.cfg"
if [ -f $isolinux_alternate_install ]; then 
  if ! grep -q "label installauto" $isolinux_alternate_install; then 
    cat << EOF >> $isolinux_alternate_install
label installauto
        menu label ^Install Automated 
        linux /install/vmlinuz
        initrd /install/initrd.gz
        append vga=788 @APPEND_INSTALL@ --- quiet file=/preseed.cfg locale=en_US.UTF-8 keymap=us hostname=kali domain=local.lan
EOF
  fi
  else
    cat << EOF >> $isolinux_alternate_install
label installauto
        menu label ^Install Automated 
        linux /install/vmlinuz
        initrd /install/initrd.gz
        append vga=788 @APPEND_INSTALL@ --- quiet file=/preseed.cfg locale=en_US.UTF-8 keymap=us hostname=kali domain=local.lan
EOF
fi

#echo
#echo "=============================================================================="
#echo "Editing isolinux to auto select our configuration for install by default"
#echo "=============================================================================="
#echo
# prompt is 0 or 1
# timeout in seconds for default choice
# automatically choose our label 'install' that we just created
#cat << EOF > /usr/share/live/build/bootloaders/isolinux/isolinux.cfg
#include menu.cfg
#default installauto
#prompt 1
#timeout 5
#EOF
#prompt 0
#timeout 0
#EOF

echo
echo "=============================================================================="
echo "Copying custom hooks"
echo "=============================================================================="
echo
# copy all hooks and make hooks executable
direc="$live_build_dir/kali-config/common/hooks/normal"
mkdir -p $direc
rm -rf $direc/*
rsync -r "/tmp/OSCPRepo/Custom Build ISO Image/hooks/" $direc
chmod +x $direc/*.chroot


echo
echo "=============================================================================="
echo "Modifying build options in auto/config"
echo "=============================================================================="
echo
# Since they give us lb_opts="", we can add our own options to be appended
# adding two options, --apt-recommends false and --debian-installer-gui false

# The best way to do an installation from the live disk is to modify --installer to be live instead of cdrom
# This will copy the entire 'live' environment and just write it to disk
sed -i 's/--debian-installer cdrom/--debian-installer live/g' "$live_build_dir/auto/config"

# To reduce size (up to 160mb), we can remove memtest
sed -i 's/--memtest memtest86/--memtest none/g' "$live_build_dir/auto/config"

echo
echo "=============================================================================="
echo "Cleaning up and building....this will take some time..."
echo "=============================================================================="
echo

# Now you can proceed to build your ISO, this process may take a while depending on your hardware and internet speeds. 

# Just to be safe, we'll clear any files that may have been added/changed between runs. Only keep our changes in kali-config/* and auto/config
# TODO: NOTE:, between runs, you'll need to copy finished ISOs out of the images dir or they will be deleted!
cd $live_build_dir
rm -rf cache/ chroot* live* config/ images/ local/

# Note that variant-default is now xfce and NOT gnome
$live_build_dir/./build.sh --distribution kali-rolling --variant $variant --verbose

# Once completed, your ISO can be found in the live-build images directory.

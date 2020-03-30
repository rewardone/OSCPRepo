#!/bin/sh
# This script provisions a bare installation to resemble the configuration of the custom iso

# intall as many packages from apt as possible:
apt-get update

variant="xfce"
install_string=""
for package in $(cat $variant/kali.list.chroot | grep -v "#"); do
  install_string="$install_string $package";
done

REM=""
for i in $install_string; do 
  res="";
  res=$(apt-cache search $i); 
  if [ -z "${res}" ]; then 
    echo "$i has been removed from kali-rolling. Make a hook or download and add the package manually!"; REM="$i $REM"; 
  fi;
done

if [ ! -z "${REM}" ]; then 
  exit 1;
fi;


apt install -y $install_string 

for hook in $(ls hooks/*.chroot); do
  cat $hook | bash;
done
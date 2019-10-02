Creating a custom ISO

If you want to build a custom ISO you can easily follow the steps at https://docs.kali.org/kali-dojo/02-mastering-live-build

This directory contains a script (setup.sh) that will automate this process. It is best to install it on a running kali system. This will build a 64-bit live CD and installation. 

The setup will download this repo into tmp in order to copy hooks, package list, and preseed into place. 
Then it will run build.sh on the default variant (gnome). 

Customization options:
Look at each hook. If they are present in the hooks/normal directory, the hook will be executed. 
Look at kali.list.chroot. This is the list of packages that will be installed. 
Variant. You can choose which variant to build (gnome, make, lxde, etc). You MUST edit the script (cp kali.list.chroot to the right location and build the right variant) AND the kali.list.chroot to include kali-<variant> visual environment to install. 
Preseed. Preseed included has default passwords, no user account, etc. 

Other flags you may look to include in the /live-build-config/auto/config script are: 

--apt-recommends false 
--apt-indices false
--clean
--debian-installer-gui false
--system normal
--cache-packages true 

The end product if yo run this script will be a 64-bit kali iso with the ability to install itself completely unattended. The current package list will have around 100 tools, several wordlists, recon scripts, enumeration scripts, the BookmarkList keepnote, and zsh with some plugins. 
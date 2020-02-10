Creating a custom installation ISO

If you want to build a custom ISO you can easily follow the steps at https://docs.kali.org/kali-dojo/02-mastering-live-build

This directory contains a script (setup.sh) that will automate this process. It is best to run it on a kali system. This will build a 64-bit installer iso.  

Future work will include an option in setup.sh to build a live ISO or an installer ISO. 

The setup.sh will 
* Download this repo into tmp in order to copy hooks, package list, preseed, and repo script/lists into place. 
* Download dependencies for live-build-config
* Determine if any packages in the package list has been removed from kali-rolling (and will fail the build)
* Configure install.cfg and isolinux for automatic boot and selection of the instal upon boot 

All variants will be built at the same time. Comment out the variants you do not want built. The default for Kali is now xfce and not gnome. 

Customization options:
* Look at each hook in the hooks directory. If they are present in the hooks/normal directory, the hook will be executed in both the live and installer image. Live images only require them to be in config/hooks/live.
* Look at kali.list.binary. This is the list of packages that will be installed in the installer image. Naming it kali.list.chroot will install packages only in the live image. Naming it kali.list will install packages in both live and installer.
* Variant. You can choose which variant to build (gnome, make, lxde, etc). When adding additional variants, ensure the package list includes that variants package requirements for its visuals).
* Preseed. Preseed included has default passwords, no user account, etc. You MUST chance the root password in the preseed. Local account support coming soon to mirror kali.2020.

Other flags you may look to include in the /live-build-config/auto/config script are: 

--apt-recommends false 
--apt-indices false
--clean 
--debian-installer-gui false
--cache-packages true 
--apt-http-proxy http://your.proxy
--memtest none

The end product if yo run this script will be a 64-bit kali iso with the ability to install itself completely unattended. The current package list will have around 100 tools, several wordlists, recon scripts, enumeration scripts, the BookmarkList keepnote, and zsh with some plugins. It is a fairly large ISO and as such can only fit either the live or the installer image on one DVD. 


Other technical notes for future debugging:
* It is possible to include a custom tasksel package. This is included in setup.sh now, but not used at the moment during install (live). 
* --installer live is key to making things easier, but using live-build increases the size of the disk. 

Some great resources:
http://xpt.sourceforge.net/techdox/nix/live/debian-cd/dcd04-DebianDistributionCD/ar01s02.html
https://d-i.debian.org/doc/internals/apb.html#idm914
https://lists.debian.org/debian-live/2011/04/msg00009.html



Changelog: 
2-2020:
 Updated for Kali.2020.1. 
 Moving lists into /usr/share/lists
 Removed packages for size/compatability constraints:
  atom
  maltego
  maltego-teeth
  veil
 Added packages:
  openssh-server
 Updated hooks:
  A few hooks have been changed to download .zip instead of cloning repos for size constraints
  cactustorch: added
  firefox: preferences and extensions added (still needs a hook for user.js)
  keepnote: Removed
  cherrytree: added
  sharpshooter: added
  vscode: added







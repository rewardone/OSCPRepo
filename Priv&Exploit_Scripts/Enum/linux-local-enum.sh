#!/bin/bash

BLACK="\033[30m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
PINK="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"
NORMAL="\033[0;39m"

# Quick Linux Local Enumeration Script 
# v1.0
#
# Provides the following functions
# Cat files:
#     /etc/issue
#     /etc/*-release
#     /etc/sysconfig/network
#     /etc/resolv.conf
#     /etc/fstab
#     /etc/passwd
#     /etc/shadow
#     /etc/group
#     /etc/sudoers
#
# Run commands:
#     uname -ar
#     df -h         			(This information  includes  the file system name, the total space
#				    			 allocated in the file system, the amount of space	allocated
#				     			to  existing  files, the total amount of space available for
#				     			the creation of new files by  unprivileged  users,  and  the
#				     			percentage  of  normally  available  space that is currently
#				     			allocated to all files on the file system. This option over-
#				     			rides the -b, -e, -n, and -t options.
#                    			)
#     mount | column -t
#     ls -ahlR /home/
#     ls -ahlR /root/
#     w			     																	##find logged on users and what they're doing
#     last			 																	##Last logged on users
#     ps -ef | /bin/grep root															##Processes running as root
#     dpkg -l																			##List installed packages for Debian/RHEL based systems
#     rpm -qa																			##List installed packages for RHEL/Debian based systems
#     chkconfig --list | grep $(runlevel | awk '{ print $2}'):on						##RHEL/CentOS services that start at Boot
#     ls /etc/init.d/																	##List of init scripts / system services
#
# Find files:
#
# find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null  ##Sticky Bit Files
# find / -perm -222 -type d 2>/dev/null 												 ##World Writable Directories
# find / -type f -perm 0777 2>/dev/null													 ##World Writable Files
# find / -user $(whoami) 2>/dev/null													 ##Files owned by Current User
#
#


cat << "EOF"
                       .
                        `:.
                          `:.
                  .:'     ,::
                 .:'      ;:'
                 ::      ;:'
                  :    .:'
                   `.  :.
          _________________________
         :                         :
     ,---:      HighOn.Coffee      :
    : ,'"`:                       :'
    `.`.  `:                     :'
      `.`-._:                   :
        `-.__`.               ,' 
    ,--------`"`-------------'--------.
     `"--.__                   __.--"'
            `""-------------""'

EOF

sleep 1.4

printf "URL: $GREEN http://highon.coffee $NORMAL \n"

sleep 0.4

printf "Version: $YELLOW 1.0 $NORMAL \n"

sleep 0.4

printf "Twitter: $BLUE @HighOn_Coffee $NORMAL \n"
sleep 0.2
printf "Author: $BLUE @Arr0way $NORMAL \n"

sleep 0.4
printf "Disclaimer: \n"
printf "\n"
printf "$RED HighOn.Coffee is not responsible for misuse or for any damage that you may cause! \n
 You agree that you use this software at your own risk. $NORMAL  \n"

printf "\n"
printf "\n"

sleep 3

printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#' 
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Linux Version" 
printf "\n"
printf "$BLUE"
printf "##" 
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/issue;
printf "\n" 
/bin/cat /etc/*-release

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Kernel Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/uname -ar

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Network Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"


/bin/cat /etc/sysconfig/network
printf "\n"
/bin/cat /etc/resolv.conf

iprintf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED File System Info"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/df -h

iprintf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Mounted File Systems with Pretty Output"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/df -h

mount | column -t

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/fstab File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/cat /etc/fstab


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/passwd File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/passwd


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/passwd File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/shadow

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/group File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/bin/cat /etc/group


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /etc/sudoers File Contents"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/cat /etc/sudoers


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Sticky Bit Files"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED World Writable Directories"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/usr/bin/find / -perm -222 -type d 2>/dev/null  


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED World Writable FIles"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/find / -type f -perm 0777 2>/dev/null

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Files Owned by Current User"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/find / -user $(whoami) 2>/dev/null


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED /home and /root Permissions"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/ls -ahlR /home/
/bin/ls -ahlR /root/ 


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Logged on Users"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/w


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Last Logged on Users"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

/usr/bin/last

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Processes Running as root"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"
/bin/ps -ef | /bin/grep root


printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED Installed Packages for RHEL / Debian Based Systems"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

# Enumarate CentOS / Ubuntu Boxes 
# This is not a great way of ID'ing a box, but I'm being lazy


printf "\n"
/usr/bin/dpkg -l

printf "\n"
/usr/bin/rpm -qa

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED CentOS / RHEL Services that start at Boot"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"

chkconfig --list | grep $(runlevel | awk '{ print $2}'):on

printf "\n"
printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "##"
printf "\n"
printf "$RED"
printf "$BLUE## $RED List of init Scripts aka System Services"
printf "\n"
printf "$BLUE"
printf "##"
printf "\n"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "\n"
printf "$NORMAL"


ls /etc/init.d/

printf "$BLUE"
printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' '#'
printf "$NORMAL"

printf "\n More Linux enumeration commands can be found at: $BLUE https://highon.coffee/docs/linux-commands  \n"

printf "\n $RED So long, and thanks for all the fish... \n $NORMAL"

printf "\n"

#!/bin/bash
#A script to enumerate local information from a Linux host
version="version 0.92"
#@rebootuser
#github.com/rewardone

#TODO, change easy "wins" that are found to color green
#TODO, ensure all feedback to user is properly informative
#TIP, find -writable specifies if the user running the find command has write access
#TODO, php checks
#TODO, nginx modules in the conf, need hands on to write a parser/grep string
#TODO, executable files/folders
#TODO, tar.gz exported files for easy transport tar zcvf archive.tar.gz file1 file2 etc
#TODO, 'interesting' file extensions. Looking for .dat,.db (more?)

#help function
#31m is red, 33m is yellow, 32m is green
usage ()
{
echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com | @rebootuser \e[00m"
echo -e "\e[00;33m# www.github.com/rewardone         \e[00m"
echo -e "\e[00;33m# $version\e[00m\n"
echo -e "\e[00;33m# Example: ./LinEnum.sh -k keyword -r report -e /tmp/ -t \e[00m\n"
echo -e "\e[00;33m# Recommended: ./LinEnum.sh -k 'pass\|password\|DB_PASS\|DB_USER' -r ReportName.txt -e /tmp/ -i 1 -t 1\e[00m\n"

		echo "OPTIONS:"
		echo "-k	Enter keyword"
		echo "-e	Enter export location"
        echo "-s    Supply user password for sudo checks (INSECURE)"
        echo "-i    Write software versions (only) to separate file: verinfo.txt"
		echo "-t	Include thorough (lengthy) tests"
		echo "-r	Enter report name"
		echo "-h	Displays this help text"
		echo -e "\n"
		echo "Running with no options = limited scans/no output file"

echo -e "\e[00;31m#########################################################\e[00m"
}

header()
{
echo -e "\n\e[00;31m#########################################################\e[00m"
echo -e "\e[00;31m#\e[00m" "\e[00;33mLocal Linux Enumeration & Privilege Escalation Script\e[00m" "\e[00;31m#\e[00m"
echo -e "\e[00;31m#########################################################\e[00m"
echo -e "\e[00;33m# www.rebootuser.com\e[00m"
echo -e "\e[00;33m# www.github.com/rewardone\e[00m"
echo -e "\e[00;33m# $version\e[00m\n"
}

##DEBUG INFO and ARGS
debug_info()
{
echo "[-] Debug Info"

if [ "$keyword" ]; then
	echo "[+] Searching for the keyword $keyword in conf, php, ini and log files"
else
	:
fi

if [ "$report" ]; then
	echo "[+] Report name = $report"
else
	:
fi

if [ "$export" ]; then
	echo "[+] Export location = $export"
else
	:
fi

if [ "$verinfo" ]; then
  echo "Software versions will also be writted to separate file: verinfo.txt"
else
  echo "Software versions will not be written to separate file"
fi

if [ "$thorough" ]; then
	echo "[+] Thorough tests = enabled"
else
	echo  -e "\e[00;33m[+] Thorough tests = Disabled (SUID/GUID checks will not be perfomed!)\e[00m"
fi

sleep 2

if [ "$export" ]; then
  mkdir $export 2>/dev/null
  format=$export/LinEnum-export-`date +"%d-%m-%y"`
  mkdir $format 2>/dev/null
else
  :
fi

if [ "$sudopass" ]; then
  echo -e "\e[00;35m[+] Please enter password - INSECURE - really only for CTF use!\e[00m"
  read -s userpassword
  echo
else
  :
fi

who=`whoami` 2>/dev/null
echo -e "\n"

echo -e "\e[00;33m[+] Scan started at:"; date
echo -e "\e[00m\n"
}

# useful binaries (thanks to https://gtfobins.github.io/)
binarylist='nmap\|perl\|awk\|find\|bash\|sh\|man\|more\|less\|vi\|emacs\|vim\|nc\|netcat\|python\|ruby\|lua\|irb\|tar\|zip\|gdb\|pico\|scp\|git\|rvim\|script\|ash\|csh\|curl\|dash\|ed\|env\|expect\|ftp\|sftp\|node\|php\|rpm\|rpmquery\|socat\|strace\|taskset\|tclsh\|telnet\|tftp\|wget\|wish\|zsh\|ssh'

#SYSTEM INFO
#hostname, issue, *-release (lsb-release, redhat-release), version, uname -arms
#reference: rpm -q kernel, dmesg | grep Linux, ls /boot | grep vmlinuz-
system_info()
{
echo -e "\e[00;33m### SYSTEM ##############################################\e[00m"

#basic kernel info
unameinfo=`uname -arms 2>/dev/null`
if [ "$unameinfo" ]; then
  echo -e "\e[00;31m[-] Kernel information:\e[00m\n$unameinfo"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $unameinfo >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

procver=`cat /proc/version 2>/dev/null`
if [ "$procver" ]; then
  echo -e "\e[00;31m[-] Kernel information (continued):\e[00m\n$procver"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $procver >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#search all *-release files for version info
release=`cat /etc/*-release 2>/dev/null`
if [ "$release" ]; then
  echo -e "\e[00;31m[-] Specific release information:\e[00m\n$release"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $release >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#search /etc/issue
issue=`cat /etc/issue 2>/dev/null`
if [ "$issue" ]; then
  echo -e "\e[00;31m[-] Etc Issue information:\e[00m\n$issue"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $issue >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#target hostname info
hostnamed=`hostname 2>/dev/null`
if [ "$hostnamed" ]; then
  echo -e "\e[00;31m[-] Hostname:\e[00m\n$hostnamed"
  echo -e "\n"
else
  :
fi
}

#USER INFO
#whoami, id, last wx, lastlog, w, env, groups
user_info()
{
echo -e "\e[00;33m### USER/GROUP ##########################################\e[00m"

#current user details
currusr=`id 2>/dev/null`
if [ "$currusr" ]; then
  echo -e "\e[00;31m[-] Current user/group info:\e[00m\n$currusr"
  echo -e "\n"
else
  :
fi

#current user details
whoamicmd=`whoami 2>/dev/null`
if [ "$whoamicmd" ]; then
  echo -e "\e[00;31m[-] Current user info:\e[00m\n$whoamicmd"
  echo -e "\n"
else
  :
fi

#last with wx args
lastcmd=`last -wx 2>/dev/null | head -n 10`
if [ "$lastcmd" ]; then
  echo -e "\e[00;31m[-] Last with system and fullnames info (head 10):\e[00m\n$lastcmd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$lastcmd" ]; then
  mkdir $format/var-export/ 2>/dev/null
  cp /var/log/wtmp $format/var-export/wtmp 2>/dev/null
else
  :
fi

#last logged on user information
lastlogedonusrs=`lastlog 2>/dev/null |grep -v "Never" 2>/dev/null`
if [ "$lastlogedonusrs" ]; then
  echo -e "\e[00;31m[-] Users that have previously logged onto the system:\e[00m\n$lastlogedonusrs"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$lastlogedonusrs" ]; then
  mkdir $format/var-export/ 2>/dev/null
  cp /var/log/lastlog $format/var-export/lastlog 2>/dev/null
else
  :
fi

#who else is logged on
loggedonusrs=`w 2>/dev/null`
if [ "$loggedonusrs" ]; then
  echo -e "\e[00;31m[-] Who else is logged on:\e[00m\n$loggedonusrs"
  echo -e "\n"
else
  :
fi
}

environmental_info()
{
echo -e "\e[00;33m### ENVIRONMENTAL #######################################\e[00m"

#env information
envinfo=`env 2>/dev/null | grep -v 'LS_COLORS' 2>/dev/null`
if [ "$envinfo" ]; then
  echo -e "\e[00;31m[-] Environment information:\e[00m\n$envinfo"
  echo -e "\n"
else
  :
fi

#check if selinux is enabled
sestatus=`sestatus 2>/dev/null`
if [ "$sestatus" ]; then
  echo -e "\e[00;31m[-] SELinux seems present:\e[00m\n$sestatus"
  echo -e "\n"
fi

#phackt

#current path configuration
pathinfo=`echo $PATH 2>/dev/null`
if [ "$pathinfo" ]; then
  echo -e "\e[00;31m[-] Path information:\e[00m\n$pathinfo"
  echo -e "\n"
else
  :
fi

#get permissions of $PATH
pathvar=`echo $PATH 2>/dev/null | sed 's/:/ /g'`
if [ "$pathvar" ]; then
  echo -e "\e[00;31m[-] Permissions of each dir in PATH:\e[00m\n"
  for i in $(echo $PATH 2>/dev/null | sed 's/:/ /g'); do
    ls -ld $i;
  done
  echo -e "\n"
else
  :
fi

#lists available shells
shellinfo=`cat /etc/shells 2>/dev/null`
if [ "$shellinfo" ]; then
  echo -e "\e[00;31m[-] Available shells:\e[00m\n$shellinfo"
  echo -e "\n"
else
  :
fi

#current umask value with both octal and symbolic output
umask=`umask -S 2>/dev/null & umask 2>/dev/null`
if [ "$umask" ]; then
  echo -e "\e[00;31m[-] Current umask value:\e[00m\n$umask"
  echo -e "\n"
else
  :
fi

#umask value as in /etc/login.defs
umaskdef=`grep -i "^UMASK" /etc/login.defs 2>/dev/null`
if [ "$umaskdef" ]; then
  echo -e "\e[00;31m[-] umask value as specified in /etc/login.defs:\e[00m\n$umaskdef"
  echo -e "\n"
else
  :
fi

#password policy information as stored in /etc/login.defs
logindefs=`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`
if [ "$logindefs" ]; then
  echo -e "\e[00;31m[-] Password and storage information:\e[00m\n$logindefs"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$logindefs" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/login.defs $format/etc-export/login.defs 2>/dev/null
else
  :
fi
}

#users in etc/passwd, user accounts from UID in etc/passwd, copy etc/passwd locally
#users in etc/groups, group membership in etc/groups, copy etc/group locally, all root (uid 0) accounts
# check for super users in /etc/passwd, check for other users	in /etc/passwd
users_and_groups()
{
echo -e "\e[00;33m### User and Group Information ####################################\e[00m"

#contents of /etc/passwd
readpasswd=`cat /etc/passwd 2>/dev/null`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/passwd:\e[00m\n$readpasswd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$readpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else
  :
fi

#list only user id's from /etc/passwd
usersfrompasswd=`cut -d":" -f1 /etc/passwd 2>/dev/null`
if [ "$usersfrompasswd" ]; then
  echo -e "\e[00;31m[-] User IDs only via /etc/passwd:\e[00m\n$usersfrompasswd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$usersfrompasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/passwd $format/etc-export/passwd 2>/dev/null
else
  :
fi

#all root accounts (uid 0)
superman=`grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null`
if [ "$superman" ]; then
  echo -e "\e[00;31m[-] Super user account(s):\e[00m\n$superman"
  echo -e "\n"
else
  :
fi

#lists all id's and respective group(s)
grpinfo=`for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null`
if [ "$grpinfo" ]; then
  echo -e "\e[00;31m[-] Group memberships via id of f1 of etc/passwd:\e[00m\n$grpinfo"
  #added by phackt - look for adm group (thanks patrick)
  adm_users=$(echo -e "$grpinfo" | grep "(adm)")
  if [[ ! -z $adm_users ]];
  then
    echo -e "\n\e[00;31m[-] Seems we met some admin users!!!\e[00m\n"
    echo -e "$adm_users\n"
  fi
  wheel_group=$(echo -e "$grpinfo" | grep "(wheel)")
  if [[ ! -z $wheelgroup ]];
  then
    echo -e "\n[-] Members of wheel (typically given access in sudoers)\n"
    echo -e "$wheel_group\n"
  fi
  echo -e "\n"
else
  :
fi

#etc/groups
groupcmd=`awk -F":" '{ print $1 " " $2 " " $3 " " $4 }' /etc/group | column -t 2>/dev/null`
groupfileheaders=`echo "GroupName Password GroupID GroupMembers" | column -t 2>/dev/null`
if [ "$groupcmd" ]; then
  echo -e "\e[00;31m[-] Groups and GroupIDs via /etc/group. May not be up to date with /etc/passwd!\e[00m\n"
  echo -e "\e[00;31m$groupfileheaders\e[00m\n$groupcmd\n"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$groupcmd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/group $format/etc-export/group 2>/dev/null
else
  :
fi

#locate custom user accounts with some 'known default' uids
readpasswd=`grep -v "^#" /etc/passwd | awk -F: '$3 == 0 || $3 == 500 || $3 == 501 || $3 == 502 || $3 == 1000 || $3 == 1001 || $3 == 1002 || $3 == 2000 || $3 == 2001 || $3 == 2002 { print }'`
if [ "$readpasswd" ]; then
  echo -e "\e[00;31m[-] Sample entires from /etc/passwd (searching for uid values 0, 500, 501, 502, 1000, 1001, 1002, 2000, 2001, 2002):\e[00m\n$readpasswd"
  echo -e "\n"
else
  :
fi
}

#hashes in /etc/passwd, read shadow, copy shadow, read master.password, copy master.password
#read sudoers, copy sudoers, sudo without password, read lib/misc/shadow, /etc/security/passwd
# users with no password in /etc/passwd
quick_passwd_wins()
{
echo -e "\e[00;33m### Password Files (Quick Wins) ####################################\e[00m"

#checks to see if any hashes are stored in /etc/passwd (depreciated  *nix storage method)
hashesinpasswd=`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`
if [ "$hashesinpasswd" ]; then
  echo -e "\e[00;33m[+] It looks like we have password hashes in /etc/passwd!\e[00m\n$hashesinpasswd"
  echo -e "\n"
else
  :
fi

#checks to see if the shadow file can be read
readshadow=`cat /etc/shadow 2>/dev/null`
if [ "$readshadow" ]; then
  echo -e "\e[00;33m[+] We can read the shadow file!\e[00m\n$readshadow"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$readshadow" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/shadow $format/etc-export/shadow 2>/dev/null
else
  :
fi

#checks to see if /etc/master.passwd can be read - BSD 'shadow' variant
readmasterpasswd=`cat /etc/master.passwd 2>/dev/null`
if [ "$readmasterpasswd" ]; then
  echo -e "\e[00;33m[+] We can read the master.passwd file!\e[00m\n$readmasterpasswd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$readmasterpasswd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/master.passwd $format/etc-export/master.passwd 2>/dev/null
else
  :
fi

#check for /etc/security/passwd
readsecuritypass=`cat /etc/security/passwd 2>/dev/null`
if [ "$readsecuritypass" ]; then
  echo -e "\e[00;33m[+] Etc/security/password file can be read:\e[00m\n$readsecuritypass"
  echo -e "\n"
else
  :
fi

#check for lib/misc/shadow
miscshadow=`cat /lib/misc/shadow 2>/dev/null`
if [ "$miscshadow" ]; then
  echo -e "\e[00;33m[+] Lib/misc/shadow file can be read:\e[00m\n$miscshadow"
  echo -e "\n"
else
  :
fi

#manual check - lists out sensitive files, can we read/modify etc.
echo -e "\e[00;31m[-] Can we read/write sensitive files:\e[00m" ; ls -la /etc/passwd 2>/dev/null ; ls -la /etc/group 2>/dev/null ; ls -la /etc/profile 2>/dev/null; ls -la /etc/shadow 2>/dev/null ; ls -la /etc/master.passwd 2>/dev/null ; ls -la /etc/sudoers 2>/dev/null
echo -e "\n"

#pull out vital sudoers info
sudoers=`grep -v -e '^$' /etc/sudoers 2>/dev/null |grep -v "#" 2>/dev/null`
if [ "$sudoers" ]; then
  echo -e "\e[00;31m[-] Sudoers configuration (condensed):\e[00m\n$sudoers" | tee -a $report 2>/dev/null
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$sudoers" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sudoers $format/etc-export/sudoers 2>/dev/null
else
  :
fi

#can we sudo without supplying a password
sudoperms=`echo '' | sudo -S -l -k 2>/dev/null`
if [ "$sudoperms" ]; then
  echo -e "\e[00;33m[+] We can sudo without supplying a password!\e[00m\n$sudoperms"
  echo -e "\n"
else
  :
fi

#check sudo perms - authenticated, can we sudo with a password
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudoauth=`echo $userpassword | sudo -S -l -k 2>/dev/null`
      if [ "$sudoauth" ]; then
        echo -e "\e[00;33m[+] We can sudo when supplying a password!\e[00m\n$sudoauth"
        echo -e "\n"
      else
        :
      fi
    fi
else
  :
fi

#who has sudoed in the past
whohasbeensudo=`find /home -name .sudo_as_admin_successful 2>/dev/null`
if [ "$whohasbeensudo" ]; then
  echo -e "\e[00;31m[-] Accounts that have recently used sudo:\e[00m\n$whohasbeensudo"
  echo -e "\n"
else
  :
fi

}

#roots home, home dir perms, enum home,
# user home directories: writable? user home directories: Readable and executable?
# user .*_history files, ~/.bash_profile, ~/.bashrc, ~/.bash_logout, ~/.bash_history
# ~/.nano_history, ~/.aftp_history, ~/.mysql_history, ~/.php_history, /etc/profile
# /etc/bashrc
home_and_user_files()
{
echo -e "\e[00;33m### Home and User File Information ####################################\e[00m"

#checks to see if roots home directory is accessible
rthmdir=`ls -ahl /root/ 2>/dev/null`
if [ "$rthmdir" ]; then
  echo -e "\e[00;33m[+] We can read root's home directory!\e[00m\n$rthmdir"
  echo -e "\n"
else
  :
fi

#displays /home directory permissions - check if any are lax
homedirperms=`ls -ahl /home/ 2>/dev/null`
if [ "$homedirperms" ]; then
  echo -e "\e[00;31m[-] Are permissions on /home directories lax:\e[00m\n$homedirperms"
  echo -e "\n"
else
  :
fi

#lists current user's home directory contents
if [ "$thorough" = "1" ]; then
homedircontents=`ls -ahl ~ 2>/dev/null`
	if [ "$homedircontents" ] ; then
		echo -e "\e[00;31m[-] Current user home directory contents:\e[00m\n$homedircontents"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

# #find all hidden files/directories in home dirs
# dothiddenfiles=`find /home -name ".*" -exec ls -lah {} \; 2>/dev/null`
# if [ "$dothiddenfiles" ]; then
  # echo -e "\e[00;31mUser hidden files/dirs detected, some may contain sensitive information:\e[00m\n$dothiddenfiles"
  # echo -e "\n"
# else
  # :
# fi

# if [ "$export" ] && [ "$dothiddenfiles" ]; then
  # mkdir $format/hidden-files/ 2>/dev/null
  # for i in $dothiddenfiles; do cp --parents $i $format/hidden-files/; done 2>/dev/null
# else
  # :
# fi

#looks for hidden files (all)
if [ "$thorough" = "1" ]; then
  hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
  if [ "$hiddenfiles" ]; then
    echo -e "\e[00;31m[-] Hidden files:\e[00m\n$hiddenfiles"
    echo -e "\n"
  else
    :
  fi
fi

#check for the /etc/profile file
etcprofilecmd=`cat /etc/profile 2>/dev/null`
if [ "$etcprofilecmd" ]; then
  echo -e "\e[00;31m[-] ETC Profile file may contain interesting information:\e[00m\n$etcprofilecmd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$etcprofilecmd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/profile $format/etc-export/profile 2>/dev/null
else
  :
fi

#check for the /etc/bash.bashrc file
etcbashrccmd=`cat /etc/bash.bashrc 2>/dev/null`
if [ "$etcbashrccmd" ]; then
  echo -e "\e[00;31m[-] ETC bash.bashrc file may contain interesting information:\e[00m\n$etcbashrccmd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$etcbashrccmd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/bashrc $format/etc-export/bashrc 2>/dev/null
else
  :
fi
}

# check for ssh files, grab ssh
# check system for readable or encrypted ssh keys
#!! check for ssh agents
# cat ~/.ssh/authorized_keys, cat ~/.ssh/identity, cat ~/.ssh/id_rsa, cat ~/.ssh/id_dsa
# cat /etc/ssh/ssh_config, cat /etc/ssh/sshd_config,
#!!cat /etc/ssh/ssh_host_dsa_key, cat /etc/ssh/ssh_host_rsa_key, cat /etc/ssh/ssh_host_key
ssh_enum()
{
echo -e "\e[00;33m### SSH Information ####################################\e[00m"

#checks for if various ssh files are accessible - this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
sshfiles=`find / \( -name "id_dsa*" -o -name "id_rsa*" -o -name "identity*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; 2>/dev/null \;`
	if [ "$sshfiles" ]; then
		echo -e "\e[00;33m[+] SSH keys/host information found in the following locations. If known_hosts, it may be crackable:\e[00m\n$sshfiles"
		echo -e "\n"
	else
		:
	fi
  else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$sshfiles" ]; then
		mkdir $format/ssh-files/ 2>/dev/null
		for i in $sshfiles; do cp --parents $i $format/ssh-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#specifically calling out known_hosts for pivoting purposes
if [ "$thorough" = "1" ]; then
sshknownhosts=`find / -name "known_hosts" -exec cat {} \; 2>/dev/null \;`
  if [ "$sshknownhosts" ]; then
    echo -e "\e[00;31m[-] Look at where this user has SSHd to (pivot/escalation opportunities even if local!):\e[00m\n$sshknownhosts"
    echo -e "\n"
  else
    :
  fi
else
  :
fi

#is root permitted to login via ssh
sshrootlogin=`grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}'`
if [ "$sshrootlogin" = "yes" ]; then
  echo -e "\e[00;31m[-] Root is allowed to login via SSH:\e[00m" ; grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$sshrootlogin" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/sshd_config $format/etc-export/sshd_config 2>/dev/null
else
  :
fi

#check ssh_config
sshconfigcmd=`cat /etc/ssh/ssh_config 2>/dev/null`
if [ "$sshconfigcmd" = "yes" ]; then
  echo -e "\e[00;31m[-] SSH config may also contain interesting settings:\e[00m\n$sshconfigcmd"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$sshconfigcmd" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/ssh_config $format/etc-export/ssh_config 2>/dev/null
else
  :
fi
}

#/etc/netsvc.conf, /etc/nsswitch.conf
authentication_information()
{
echo -e "\e[00;33m### Authentication Information ####################################\e[00m"

#cat /etc/netsvc.conf
netsvcconf=`cat /etc/netsvc.conf 2>/dev/null`
if [ "$netsvcconf" ]; then
  echo -e "\e[00;31m[-] Etc Netsvc conf information. Identify NIS or LDAP if available:\e[00m\n$netsvcconf"
  echo -e "\n"
else
  :
fi

#cat /etc/nsswitch.conf
nsswitchconf=`cat /etc/nsswitch.conf 2>/dev/null`
if [ "$nsswitchconf" ]; then
  echo -e "\e[00;31m[-] Etc  Nsswitch conf information. Identify NIS or LDAP if available:\e[00m\n$nsswitchconf"
  echo -e "\n"
else
  :
fi

#cat pam.conf
pamconf=`cat /etc/pam.conf 2>/dev/null`
if [ "$pamconf" ]; then
  echo -e "\e[00;31m[-] Pam authentication information. Pam.conf used if pam.d modules do not exist. Order matters:\e[00m\n$pamconf"
  echo -e "\n"
else
  :
fi

#ls pam.d dir
pamdconf=`ls -alh /etc/pam.d 2>/dev/null`
if [ "$pamdconf" ]; then
  echo -e "\e[00;31m[-] Specific pam auth modules. These are used if available and /etc/pam.conf used if they are not.\e[00m\n$pamdconf"
  echo -e "\n"
  pamdconfwrite=`find /etc/pam.d/ -type f -writable -exec ls -alh {} \; 2>/dev/null`
  if [ "$pamdconfwrite" ]; then
    echo -e "\e[00;33m[+] Your user can write to these pam.d modules!:\e[00m\n$pamdconfwrite"
    echo -e "\n"
  else
    :
  fi
else
  :
fi
}

#/etc/fstab, mount | column -t, df -h
mount_information()
{
echo -e "\e[00;33m### Mount Information ####################################\e[00m"

#list nfs shares/permisisons etc.
nfsexports=`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null`
if [ "$nfsexports" ]; then
  echo -e "\e[00;31m[-] NFS config details: \e[00m\n$nfsexports"
  echo -e "\n"
  else
  :
fi

if [ "$export" ] && [ "$nfsexports" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/exports $format/etc-export/exports 2>/dev/null
else
  :
fi

if [ "$thorough" = "1" ]; then
  #phackt
  #displaying /etc/fstab
  fstab=`cat /etc/fstab 2>/dev/null`
  if [ "$fstab" ]; then
    echo -e "\e[00;31m[-] NFS displaying partitions and filesystems - you need to check if exotic filesystems\e[00m"
    echo -e "$fstab"
    echo -e "\n"
  fi
fi

#looking for credentials in /etc/fstab
fstab=`grep username /etc/fstab 2>/dev/null |awk '{sub(/.*\username=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo username: 2>/dev/null; grep password /etc/fstab 2>/dev/null |awk '{sub(/.*\password=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo password: 2>/dev/null; grep domain /etc/fstab 2>/dev/null |awk '{sub(/.*\domain=/,"");sub(/\,.*/,"")}1' 2>/dev/null| xargs -r echo domain: 2>/dev/null`
if [ "$fstab" ]; then
  echo -e "\e[00;33m[+] Looks like there are credentials in /etc/fstab!\e[00m\n$fstab"
  echo -e "\n"
  else
  :
fi

if [ "$export" ] && [ "$fstab" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else
  :
fi

fstabcred=`grep cred /etc/fstab 2>/dev/null |awk '{sub(/.*\credentials=/,"");sub(/\,.*/,"")}1' 2>/dev/null | xargs -I{} sh -c 'ls -la {}; cat {}' 2>/dev/null`
if [ "$fstabcred" ]; then
    echo -e "\e[00;33m[+] /etc/fstab contains a credentials file!\e[00m\n$fstabcred"
    echo -e "\n"
    else
    :
fi

if [ "$export" ] && [ "$fstabcred" ]; then
  mkdir $format/etc-exports/ 2>/dev/null
  cp /etc/fstab $format/etc-exports/fstab done 2>/dev/null
else
  :
fi

mountcmd=`mount 2>/dev/null | column -t`
if [ "$mountcmd" ]; then
  echo -e "\e[00;31m[-] Full mount command output:\e[00m\n$mountcmd"
  echo -e "\n"
  grepnoexec=`mount 2>/dev/null | grep -i "noexec" | awk '{print $1 " " $2 " " $3 " " $6}' | column -t`
  grepvnoexec=`mount 2>/dev/null | grep -iv "noexec" | awk '{print $1 " " $2 " " $3 " " $6}' | column -t`
  grepvnosuid=`mount 2>/dev/null | grep -iv "nosuid" | awk '{print $1 " " $2 " " $3 " " $6}' | column -t`
  grepvnodev=`mount 2>/dev/null | grep -iv "nodev" | awk '{print $1 " " $2 " " $3 " " $6}' | column -t`
  unamecmd=`uname -r 2>/dev/null`
  if [ "$grepnoexec" ]; then
    echo -e "\e[00;31m[-] Mounts with 'noexec' detcted. If $unamecmd < 2.4.25 / 2.6.0, then /lib/ld*.so execution bypass may work.\e[00m\n$grepnoexec"
  else
    :
  fi
  if [ "$grepvnoexec" ]; then
    echo -e "\e[00;31m[-] Mounts without 'noexec' detcted!\e[00m\n$grepvnoexec"
  else
    :
  fi
  if [ "$grepvnosuid" ]; then
    echo -e "\e[00;31m[-] Mounts without 'nosuid' detected!\e[00m\n$grepvnosuid"
  else
    :
  fi
  if [ "$grepvnodev" ]; then
    echo -e "\e[00;31m[-] Mounts without 'nodev' detected!\e[00m\n$grepvnodev"
  else
    :
  fi
else
  :
fi

dfcmd=`df -h 2>/dev/null`
if [ "$dfcmd" ]; then
  echo -e "\e[00;31m[-] DF command output:\e[00m\n$dfcmd"
  echo -e "\n"
else
  :
fi
}

# files with sticky bit (+sS), files owned by current user
# for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done
# Looks in 'common' places: /bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin and any other *bin, for SGID or SUID (Quicker search)
# find / -perm -g=s -type f 2>/dev/null    								# SGID (chmod 2000) - exec as the group, not the user who started it.
# find / -perm -u=s -type f 2>/dev/null    								# SUID (chmod 4000) - exec as the owner, not the user who started it
# find requires space before and after \( \) in order to function
# find -exec ls -lah {} is not what you want for dirs
special_perm_files()
{
echo -e "\e[00;33m### Special Permission Files ####################################\e[00m"
rootcheck=`id -u`

#Find all SUID files, only on thorough
if [ "$thorough" = "1" ]; then
  suidcmd=`find / \( -perm -4000 -a -type f \) -exec ls -lah {} \; 2>/dev/null`
  if [ "$suidcmd" ]; then
    echo -e "\e[00;31m[-] All SUID files. These exec as the file owner!:\e[00m\n$suidcmd"
    echo -e "\n"
  else
    :
  fi
else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$suidcmd" ]; then
		mkdir $format/suid-files/ 2>/dev/null
		for i in $suidcmd; do cp --parents $i $format/suid-files/ ; done 2>/dev/null
	else
		:
	fi
else
	:
fi

#Find certain SUID files, only on thorough
if [ "$thorough" = "1" ]; then
  certainsuidcmd=`find / \( -perm -4000 -a -type f \) -exec ls -lah {} \; 2>/dev/null | grep -iw 'ash\|awk\|base64\|bash\|busybox\|cat\|csh\|curl\|cut\|dash\|dd\|diff\|docker\|ed\|emacs\|env\|expand\|expect\|find\|flock\|fmt\|fold\|git\|head\|ionice\|jq\|ksh\|ld.so\|less\|lua\|make\|man\|more\|nano\|nc\|nice\|nl\|nmap\|node\|od\|perl\|pg\|php\|pico\|python2\|python3\|rlwrap\|rpm\|rpmquery\|rsync\|scp\|sed\|setarch\|shuf\|socat\|sort\|sqlite3\|stdbuf\|strace\|tail\|tar\|taskset\|tclsh\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|xargs\|xxd\|zip\|zsh'`
  if [ "$certainsuidcmd" ]; then
    echo -e "\e[00;33m[+] Certain SUID files. These exec as the file owner and are abusable!:\e[00m\n$certainsuidcmd"
    echo -e "\n"
  else
    :
  fi
else
  :
fi

#Find all SUID dirs, only on thorough
# if [ "$thorough" = "1" ]; then
#   suidcmd2=`find / \( -perm -4000 -a -type d \) 2>/dev/null`
#   if [ "$suidcmd2" ]; then
#     echo -e "\e[00;31mAll SUID drs. These exec as the file owner!:\e[00m\n$suidcmd2"
#     echo -e "\n"
#   else
#     :
#   fi
# else
#   :
# fi
#
# if [ "$thorough" = "1" ]; then
# 	if [ "$export" ] && [ "$suidcmd2" ]; then
# 		mkdir $format/suid-files/ 2>/dev/null
# 		for i in $suidcmd2; do cp --parents $i $format/suid-files/ ; done 2>/dev/null
# 	else
# 		:
# 	fi
# else
# 	:
# fi

#lists world-writable suid files owned by root
if [ "$thorough" = "1" ]; then
wwsuidrt=`find / -uid 0 -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwsuidrt" ]; then
		echo -e "\e[00;33m[+] World-writable SUID files, these exec as file owner: root, and you can write!:\e[00m\n$wwsuidrt"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

#lists word-writable suid files
if [ "$thorough" = "1" ]; then
wwsuid=`find / -perm -4007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwsuid" ]; then
		echo -e "\e[00;33m[+] World-writable SUID files, these exec as file owner and you can write!:\e[00m\n$wwsuid"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

#Find all GUID files, only on thorough
if [ "$thorough" = "1" ]; then
  guidcmd=`find / \( -perm -2000 -a -type f \) -exec ls -lah {} \; 2>/dev/null`
  if [ "$guidcmd" ]; then
    echo -e "\e[00;31m[-] All GUID files. These exec as the group!:\e[00m\n$guidcmd"
    echo -e "\n"
  else
    :
  fi
else
  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$guidcmd" ]; then
		mkdir $format/guid-files/ 2>/dev/null
		for i in $guidcmd; do cp --parents $i $format/guid-files/ ; done 2>/dev/null
	else
		:
	fi
else
	:
fi

#Find all GUID dirs, only on thorough
# if [ "$thorough" = "1" ]; then
#   if [ "$rootcheck" != "0" ]; then
#     guidcmd2=`find / \( -perm -2000 -a -type d \) 2>/dev/null`
#   else
#     echo -e "All GUID Dirs: You're running under UID 0, too many files to list...\n"
#   fi
#   if [ "$guidcmd2" ]; then
#     echo -e "\e[00;31mAll GUID dirs. These exec as the group!:\e[00m\n$guidcmd2"
#     echo -e "\n"
#   else
#     :
#   fi
# else
#   :
# fi
#
# if [ "$thorough" = "1" ]; then
# 	if [ "$export" ] && [ "$guidcmd2" ]; then
# 		mkdir $format/guid-files/ 2>/dev/null
# 		for i in $guidcmd2; do cp --parents $i $format/guid-files/ ; done 2>/dev/null
# 	else
# 		:
# 	fi
# else
# 	:
# fi

#list of 'interesting' guid files - feel free to make additions
if [ "$thorough" = "1" ]; then
intguid=`find / -perm -2000 -type f  -exec ls -la {} \; 2>/dev/null | grep -w $binarylist 2>/dev/null`
	if [ "$intguid" ]; then
		echo -e "\e[00;33m[+] Possibly interesting GUID files:\e[00m\n$intguid"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

#lists world-writable guid files
if [ "$thorough" = "1" ]; then
wwguid=`find / -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwguid" ]; then
		echo -e "\e[00;33m[+] World-writable GUID files, these exec as the group and you can write!:\e[00m\n$wwguid"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

#lists world-writable guid files owned by root
if [ "$thorough" = "1" ]; then
wwguidrt=`find / -uid 0 -perm -2007 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwguidrt" ]; then
		echo -e "\e[00;33m[+] World-writable GUID files, these exec as the group, owned by root, and you can write!:\e[00m\n$wwguidrt"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi


#list all files with POSIX capabilities set along with there capabilities
if [ "$thorough" = "1" ]; then
fileswithcaps=`getcap -r / 2>/dev/null || /sbin/getcap -r / 2>/dev/null`
	if [ "$fileswithcaps" ]; then
		echo -e "\e[00;33m[+] Files with POSIX capabilities set:\e[00m\n$fileswithcaps"
		echo -e "\n"
	else
		:
	fi
  else
	  :
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$fileswithcaps" ]; then
		mkdir $format/files_with_capabilities/ 2>/dev/null
		for i in $fileswithcaps; do cp $i $format/files_with_capabilities/; done 2>/dev/null
	else
		:
	fi
  else
	  :
fi

#searches /etc/security/capability.conf for users associated capapilies
if [ "$thorough" = "1" ]; then
userswithcaps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null`
	if [ "$userswithcaps" ]; then
		echo -e "\e[00;33m[+] Users with specific POSIX capabilities:\e[00m\n$userswithcaps"
		echo -e "\n"
	else
		:
	fi
  else
	  :
fi

if [ "$thorough" = "1" ] && [ "$userswithcaps" ] ; then
#matches the capabilities found associated with users with the current user
matchedcaps=`echo -e "$userswithcaps" | grep \`whoami\` | awk '{print $1}' 2>/dev/null`
	if [ "$matchedcaps" ]; then
		echo -e "\e[00;33m[+] Capabilities associated with the current user:\e[00m\n$matchedcaps"
		echo -e "\n"
		#matches the files with capapbilities with capabilities associated with the current user
		matchedfiles=`echo -e "$matchedcaps" | while read -r cap ; do echo -e "$fileswithcaps" | grep "$cap" ; done 2>/dev/null`
		if [ "$matchedfiles" ]; then
			echo -e "\e[00;33m[+] Files with the same capabilities associated with the current user (You may want to try abusing those capabilties):\e[00m\n$matchedfiles"
			echo -e "\n"
			#lists the permissions of the files having the same capabilies associated with the current user
			matchedfilesperms=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do ls -la $f ;done 2>/dev/null`
			echo -e "\e[00;33m[+] Permissions of files with the same capabilities associated with the current user:\e[00m\n$matchedfilesperms"
			echo -e "\n"
			if [ "$matchedfilesperms" ]; then
				#checks if any of the files with same capabilities associated with the current user is writable
				writablematchedfiles=`echo -e "$matchedfiles" | awk '{print $1}' | while read -r f; do find $f -writable -exec ls -la {} + ;done 2>/dev/null`
				if [ "$writablematchedfiles" ]; then
					echo -e "\e[00;33m[+] User/Group writable files with the same capabilities associated with the current user:\e[00m\n$writablematchedfiles"
					echo -e "\n"
				else
					:
				fi
			else
				:
			fi
		else
			:
		fi
	else
		:
	fi
  else
	  :
fi


#Only find files in the bin dirs with perm 4000 or 2000
# suidguid=`for i in \`locate -r "bin$"\`; do find $i \( -perm -4000 -o -perm -2000 \) -type f -exec ls -lah {} \; 2>/dev/null; done`
# if [ "$suidguid" ]; then
#   echo -e "\e[00;31mSUID and GUID files from bin directories. These exec as group or owner!:\e[00m\n$suidguid"
#   echo -e "\n"
# else
#   :
# fi
#
# if [ "$export" ] && [ "$suidguid" ]; then
# 	mkdir $format/suidguid-files/ 2>/dev/null
# 	for i in $suidguid; do cp --parents $i $format/suidguid-files/ ; done 2>/dev/null
# else
# 	:
# fi

#Find dirs with sticky bit set
stickydirs=`find / \( -perm -1000 -a -type d \) 2>/dev/null`
if [ "$stickydirs" ]; then
  echo -e "\e[00;31m[-] These dirs have the sticky bit set (no deletions unless you're the owner):\e[00m\n$stickydirs"
  echo -e "\n"
else
  :
fi

#Find files with sticky bit set
stickyfiles=`find / \( -perm -1000 -a -type f \) -exec ls -lah {} \; 2>/dev/null`
if [ "$stickyfiles" ]; then
  echo -e "\e[00;31m[-] These files have the sticky bit set (no deletions unless you're the owner):\e[00m\n$stickyfiles"
  echo -e "\n"
else
  :
fi

#Only find files in the home dirs with perm 4000 or 2000
# suidguid2=`for i in \`locate -r "home$"\`; do find $i \( -perm -4000 -o -perm -2000 \) -type f -exec ls -lah {} \; 2>/dev/null; done`
# if [ "$suidguid2" ]; then
#   echo -e "\e[00;31mSUID and GUID files from home. These exec as group or owner!:\e[00m\n$suidguid2"
#   echo -e "\n"
# else
#   :
# fi
#
# if [ "$export" ] && [ "$suidguid2" ]; then
# 	mkdir $format/suidguid2-files/ 2>/dev/null
# 	for i in $suidguid2; do cp --parents $i $format/suidguid2-files/ ; done 2>/dev/null
# else
# 	:
# fi

#Only find files you are the owner of
rootcheck=`id -u`
if [ "$rootcheck" != "0" ]; then
  mystuff=`find / \( -path /proc \) -prune \( -user \`whoami\` -a -type f \) -exec ls -alh {} \; 2>/dev/null`
else
  echo -e "[-] Files you are the owner of: You're running under UID 0, too many files to list...\n"
fi
if [ "$mystuff" ]; then
  echo -e "\e[00;31m[-] Files that this user owns\e[00m\n$mystuff"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$mystuff" ]; then
  mkdir $format/my-files/ 2>/dev/null
	for i in $mystuff; do cp --parents $i $format/my-files/ ; done 2>/dev/null
else
	:
fi

#Only find dirs you own
if [ "$rootcheck" != "0" ]; then
  mystuff2=`find / \( -path /proc \) -prune \( -user \`whoami\` -a -type d \) 2>/dev/null`
else
  echo -e "[-] Dirs you are the owner of: You're running under UID 0, too many files to list...\n"
fi
if [ "$mystuff2" ]; then
  echo -e "\e[00;31m[-] Dirs that this user owns\e[00m\n$mystuff2"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$mystuff2" ]; then
  mkdir $format/my-files/ 2>/dev/null
	for i in $mystuff2; do cp --parents $i $format/my-files/ ; done 2>/dev/null
else
	:
fi
}

# find / -perm -o x -type d 2>/dev/null     							# world-executable folders
#too much feedback at the moment
executable_files_folders()
{
#echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m"

worldwrite=`find / \( -perm -o x -type d \) 2>/dev/null | grep -v "denied"`
}

# find / -writable -type d 2>/dev/null      							    # world-writeable folders
# find / -perm -222 -type d 2>/dev/null     							    # world-writeable folders
# find / -perm -o w -type d 2>/dev/null     							    # world-writeable folders
# find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   		    # world-writeable files
# ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     					    # Anyone - write
# ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null      					    # Owner
# ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    					    # Group
#group writable files,
# find /dir -xdev \( -nouser -o -nogroup \) -print   					    # Noowner files
writeable_files_folders()
{
echo -e "\e[00;33m### Writable Files ####################################\e[00m"

# world-writeable & executable folders
writeandexec=`find / \( -perm -o=w -a -perm -o=x -a -type d \) 2>/dev/null`
if [ "$writeandexec" ]; then
  echo -e "\e[00;31m[-] Writeable and executable folders:\e[00m\n$writeandexec"
  echo -e "\n:"
else
  :
fi

#list all world-writable files excluding /proc and /sys
if [ "$thorough" = "1" ]; then
wwfiles=`find / ! -path "*/proc/*" ! -path "/sys/*" -perm -2 -type f -exec ls -la {} 2>/dev/null \;`
	if [ "$wwfiles" ]; then
		echo -e "\e[00;31m[-] World-writable files (excluding /proc and /sys):\e[00m\n$wwfiles"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wwfiles" ]; then
		mkdir $format/ww-files/ 2>/dev/null
		for i in $wwfiles; do cp --parents $i $format/ww-files/; done 2>/dev/null
	else
		:
	fi
  else
	:
fi

#Group writable files
if [ "$rootcheck" != "0" ]; then
  groupwrite=`find / \( -path /proc \) -prune \( -perm -g=w -a -type f \) -exec ls -lah {} \; 2>/dev/null`
else
  echo -e "[-] Group writable files: You're running under UID 0, too many files to list...\n"
fi
if [ "$groupwrite" ]; then
  echo -e "\e[00;31m[-] Group writeable files:\e[00m\n$groupwrite"
  echo -e "\n"
else
  :
fi

#looks for files we can write to that don't belong to us
if [ "$thorough" = "1" ]; then
  if [ "$rootcheck" != "0" ]; then
    grfilesall=`find / -writable -not -user \`whoami\` -type f -not -path "/proc/*" -exec ls -alh {} \; 2>/dev/null`
  else
    echo -e "[-] Files you can write that you don't own: You're running under UID 0, too many files to list...\n"
  fi
  if [ "$grfilesall" ]; then
    #may want to exclude /sys/ here as well
    echo -e "\e[00;31m[-] Files not owned by user but writable:\e[00m\n$grfilesall"
    echo -e "\n"
  else
    :
  fi
fi

#Odd files with no owner or group
# noownergroup=`find / \( -nouser -o -nogroup -type f -a -not -name "." -a -not -name ".." \) -exec ls -lah {} \; 2>/dev/null`
# if [ "$noownergroup" ]; then
#   echo -e "\e[00;31mFiles that have no owner and no group:\e[00m\n$noownergroup"
#   echo -e "\n"
# else
#   :
# fi
}

# find /etc/ -readable -type f 2>/dev/null               				# Anyone - read
# find /etc/ -readable -type f -maxdepth 1 2>/dev/null   				# Anyone - read
# world readable files,
readable_files_folders()
{
echo -e "\e[00;33m### Readable Files ####################################\e[00m"

#looks for world-reabable files within /home - depending on number of /home dirs & files, this can take some time so is only 'activated' with thorough scanning switch
if [ "$thorough" = "1" ]; then
wrfileshm=`find /home/ -perm -4 -type f -exec ls -al {} \; 2>/dev/null`
	if [ "$wrfileshm" ]; then
		echo -e "\e[00;31m[-] World-readable files within /home:\e[00m\n$wrfileshm"
		echo -e "\n"
	else
		:
	fi
  else
	:
fi

if [ "$thorough" = "1" ]; then
	if [ "$export" ] && [ "$wrfileshm" ]; then
		mkdir $format/wr-files/ 2>/dev/null
		for i in $wrfileshm; do cp --parents $i $format/wr-files/ ; done 2>/dev/null
	else
		:
	fi
  else
	:
fi
}

# ls -al /etc/cron* 2>/dev/null											#scheduled cron jobs
# ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null			#writable cron directories
# cat /etc/crontab
# ls -alh /var/spool/cron
# cat /etc/anacrontab
# ls -al /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null	#anacrontab
# ls -la /var/spool/anacron 2>/dev/null
# crontab -l
# ls -al /etc/ | grep cron
# ls -al /etc/cron*
# cat /etc/cron*
#!!cat /etc/at.allow
#!!cat /etc/at.deny
#!!cat /etc/cron.allow
#!!cat /etc/cron.deny
#!!cat /var/spool/cron/crontabs/root
job_info()
{
echo -e "\e[00;33m### JOBS/TASKS ##########################################\e[00m"

#are there any cron jobs configured
cronjobs=`ls -la /etc/cron* 2>/dev/null`
if [ "$cronjobs" ]; then
  echo -e "\e[00;31m[-] Cron jobs:\e[00m\n$cronjobs"
  echo -e "\n"
else
  :
fi

#can we manipulate these jobs in any way
cronjobwwperms=`find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$cronjobwwperms" ]; then
  echo -e "\e[00;33m[+] World-writable cron jobs and file contents:\e[00m\n$cronjobwwperms"
  echo -e "\n"
else
  :
fi

#contab contents
crontab=`cat /etc/crontab 2>/dev/null`
if [ "$crontab" ]; then
  echo -e "\e[00;31m[-] Crontab contents:\e[00m\n$crontab"
  echo -e "\n"
else
  :
fi

crontabvar=`ls -la /var/spool/cron/crontabs 2>/dev/null`
if [ "$crontabvar" ]; then
  echo -e "\e[00;31m[-] Anything interesting in /var/spool/cron/crontabs:\e[00m\n$crontabvar"
  echo -e "\n"
else
  :
fi

anacronjobs=`ls -la /etc/anacrontab 2>/dev/null; cat /etc/anacrontab 2>/dev/null`
if [ "$anacronjobs" ]; then
  echo -e "\e[00;31m[-] Anacron jobs and associated file permissions:\e[00m\n$anacronjobs"
  echo -e "\n"
else
  :
fi

anacrontab=`ls -la /var/spool/anacron 2>/dev/null`
if [ "$anacrontab" ]; then
  echo -e "\e[00;31m[-] When were jobs last executed (/var/spool/anacron contents):\e[00m\n$anacrontab"
  echo -e "\n"
else
  :
fi

#pull out account names from /etc/passwd and see if any users have associated cronjobs (priv command)
cronother=`cut -d ":" -f 1 /etc/passwd | xargs -n1 crontab -l -u 2>/dev/null`
if [ "$cronother" ]; then
  echo -e "\e[00;31m[-] Jobs held by all users:\e[00m\n$cronother"
  echo -e "\n"
else
  :
fi

# list systemd timers
if [ "$thorough" = "1" ]; then
  # include inactive timers in thorough mode
  systemdtimers="$(systemctl list-timers --all 2>/dev/null)"
  info=""
else
  systemdtimers="$(systemctl list-timers 2>/dev/null |head -n -1 2>/dev/null)"
  # replace the info in the output with a hint towards thorough mode
  info="\e[2mEnable thorough tests to see inactive timers\e[00m"
fi
if [ "$systemdtimers" ]; then
  echo -e "\e[00;31m[-] Systemd timers:\e[00m\n$systemdtimers\n$info"
  echo -e "\n"
else
  :
fi
}

# arp -a/e #e is better formatted automatically							#ARP information
# /etc/resolv.conf | grep "nameserver"									#DNS settings
# route, ifconfig, ip addr show, /sbin/route -nee, cat /etc/network/interfaces
# cat /etc/sysconfig/network, cat /etc/networks, netstat -antup -e/ee is verbosity
# netstat -tulpn -e/ee is verbosity
#!!lsof -i tcp -n -P -R, !!lsof -i udp -n -P -R, !!grep 80 /etc/services
#!!chkconfig --list, !!chkconfig --list | grep 3:on  #not default utility, must be SU
networking_info()
{
echo -e "\e[00;33m### NETWORKING  ##########################################\e[00m"

#nic information
nicinfo=`/sbin/ifconfig -a 2>/dev/null`
if [ "$nicinfo" ]; then
  echo -e "\e[00;31m[-] Network & IP info:\e[00m\n$nicinfo"
  echo -e "\n"
else
  :
fi

#ip cmd for newer distros
ipcmd=`/sbin/ip a 2>/dev/null`
if [ ! "$nicinfo" ] && [ "$ipcmd" ]; then
  echo -e "\e[00;31m[-] Network and IP info:\e[00m\n$ipcmd"
  echo -e "\n"
else
  :
fi

#ARP info, -e vs -a
arpinfo=`arp -e 2>/dev/null`
if [ "$arpinfo" ]; then
  echo -e "\e[00;31m[-] ARP history:\e[00m\n$arpinfo"
  echo -e "\n"
else
  :
fi

arpinfoip=`ip n 2>/dev/null`
if [ ! "$arpinfo" ] && [ "$arpinfoip" ]; then
  echo -e "\e[00;31m[-]  ARP history:\e[00m\n$arpinfoip"
  echo -e "\n"
else
  :
fi

#dns settings
nsinfo=`grep "nameserver" /etc/resolv.conf 2>/dev/null`
if [ "$nsinfo" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfo"
  echo -e "\n"
else
  :
fi

nsinfosysd=`systemd-resolve --status 2>/dev/null`
if [ "$nsinfosysd" ]; then
  echo -e "\e[00;31m[-] Nameserver(s):\e[00m\n$nsinfosysd"
  echo -e "\n"
else
  :
fi

#default route configuration
defroute=`route -n 2>/dev/null | grep default`
if [ "$defroute" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defroute"
  echo -e "\n"
else
  :
fi

#default route configuration
defrouteip=`ip r 2>/dev/null | grep default`
if [ ! "$defroute" ] && [ "$defrouteip" ]; then
  echo -e "\e[00;31m[-] Default route:\e[00m\n$defrouteip"
  echo -e "\n"
else
  :
fi

#interfaces config
interfacescmd=`cat /etc/network/interfaces 2>/dev/null`
if [ "$interfacescmd" ]; then
  echo -e "\e[00;31m[-] Etc/network/interfaces config:\e[00m\n$interfacescmd"
  echo -e "\n"
else
  :
fi

#network config
networkcmd=`cat /etc/sysconfig/network 2>/dev/null`
if [ "$networkcmd" ]; then
  echo -e "\e[00;31m[-] Etc/sysconfig/network config:\e[00m\n$networkcmd"
  echo -e "\n"
else
  :
fi

#networks
networkscmd2=`cat /etc/networks 2>/dev/null`
if [ "$networkscmd2" ]; then
  echo -e "\e[00;31m[-] Etc/networks config:\e[00m\n$networkscmd2"
  echo -e "\n"
else
  :
fi

###FIREWALLS and FIREWALL CHECKS
#IPTables
iptablescmd=`iptables -L 2>/dev/null`
if [ "$iptablescmd" ]; then
  configwc=`iptables --list --numeric | grep -v "^[(Chain|target|$)]" | wc -l | tr -d ''`
  if [ "$configwc" ]; then
    echo -e "\e[00;31m[-] IPTables does not appear to be configured.\e[00m\n$iptablescmd"
    echo -e "\n"
  else
    echo -e "\e[00;31m[-] IPTables listing:\e[00m\n$iptablescmd"
    echo -e "\n"
  fi
else
  :
fi

#pf
pfexist=`cat /def/pf 2>/dev/null`
if [ "$pfexist" ]; then
  echo -e "\e[00;31m[-] PF firewall exists.\e[00m\n$pfexist"
  echo -e "\n"
else
  :
fi

#pfconfig
pfconf=`cat /etc/pf.conf 2>/dev/null`
if [ "$pfconf" ]; then
  echo -e "\e[00;31m[-] Etc pf.conf. Manually check.\e[00m\n$pfconf"
  echo -e "\n"
else
  :
fi

#/etc/csf/csf.conf
csfconf=`cat /etc/csf/csf.conf 2>/dev/null`
if [ "$csfconf" ]; then
  echo -e "\e[00;31m[-] Etc csf conf. Manually check.\e[00m\n$csfconf"
  echo -e "\n"
else
  :
fi

#MacOS firewall
macosxfw=`/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep "Firewall is enabled"`
if [ ! -z "$macosxfw" ]; then
  echo -e "\e[00;31m[-] MacOS X Firewall is enabled\e[00m\n"
  echo -e "\n"
else
  :
fi

#listening TCP
tcpservs=`netstat -antpl 2>/dev/null`
if [ "$tcpservs" ]; then
  echo -e "\e[00;31m[-] Don't forget about LSOF. Netstat listening TCP.:\e[00m\n$tcpservs"
  echo -e "\n"
else
  :
fi

tcpservsip=`ss -t 2>/dev/null`
if [ ! "$tcpservs" ] && [ "$tcpservsip" ]; then
  echo -e "\e[00;31m[-] Listening TCP:\e[00m\n$tcpservsip"
  echo -e "\n"
else
  :
fi

#listening UDP
udpservs=`netstat -anupl 2>/dev/null`
if [ "$udpservs" ]; then
  echo -e "\e[00;31m[-] Don't forget about LSOF. Netstat listening UDP:\e[00m\n$udpservs"
  echo -e "\n"
else
  :
fi

udpservsip=`ip -u 2>/dev/null`
if [ ! "$udpservs" ] && [ "$udpservsip" ]; then
  echo -e "\e[00;31m[-] Listening UDP:\e[00m\n$udpservsip"
  echo -e "\n"
else
  :
fi

}

# /etc/hosts.equiv
# /etc/shosts.equiv
# aux, inetd.conf, xinetd.conf, init.d, rc.d/init.d,
services_info()
{
echo -e "\e[00;33m### PROCESSES #############################################\e[00m"

#processes running as NOT root
psaux=`ps axo user:10,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm 2>/dev/null | grep -v root | awk '{print $1 " " $2 " " $5 " " $6 " " $9 " " $10 " " $11}' | column -t`
if [ "$psaux" ]; then
  echo -e "\e[00;31m[-] Processes that are NOT running as root:\e[00m\n$psaux"
  echo -e "\n"
else
  :
fi

psauxnotus=`ps axo user:10,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm 2>/dev/null | grep -iv root | grep -iv \`whoami\` | awk '{print $1 " " $2 " " $5 " " $6 " " $9 " " $10 " " $11}' | column -t`
if [ "$psauxnotus" ]; then
  echo -e "\e[00;31m[-] Processes that are NOT running as root or `whoami`:\e[00m\n$psauxnotus"
  echo -e "\n"
else
  :
fi

#processes running as root
psauxroot=`ps aux 2>/dev/null | grep root | awk '{print $1 " " $2 " " $5 " " $6 " " $9 " " $10 " " $11}' | column -t`
if [ "$psauxroot" ]; then
  echo -e "\e[00;33m[+] Processes that are running as root! Scrutinize these:\e[00m\n$psauxroot"
  echo -e "\n"
else
  :
fi

pstree=`pstree -au 2>/dev/null`
if [ "$pstree" ]; then
  echo -e "\e[00;33m[-] Pretty tree formatting curtesy of pstree -au:\e[00m\n$pstree"
  echo -e "\n"
else
  :
fi

#Commented only because it was too noisy
#lookup process binary path and permissisons
# procperm=`ps aux 2>/dev/null | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++' 2>/dev/null`
# if [ "$procperm" ]; then
#   echo -e "\e[00;31mProcess binaries & associated permissions (from above list):\e[00m\n$procperm"
#   echo -e "\n"
# else
#   :
# fi
#
# if [ "$export" ] && [ "$procperm" ]; then
#   procpermbase=`ps aux 2>/dev/null | awk '{print $11}' | xargs -r ls 2>/dev/null | awk '!x[$0]++' 2>/dev/null`
#   mkdir $format/ps-export/ 2>/dev/null
#   for i in $procpermbase; do cp --parents $i $format/ps-export/; done 2>/dev/null
# else
#   :
# fi

#RHEL/Cent OS Services
rhservices=`chkconfig --list 2>/dev/null | grep $(runlevel | awk '{ print $2 }'):on	2>/dev/null` ##RHEL/CentOS services that start at Boot
if [ "$rhservices" ]; then
  echo -e "\e[00;31m[-] Chkconfig --list of services that start on  boot:\e[00m\n$rhservices"
  echo -e "\n"
else
  :
fi

#anything 'useful' in inetd.conf
inetdread=`cat /etc/inetd.conf 2>/dev/null`
if [ "$inetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/inetd.conf:\e[00m\n$inetdread"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$inetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/inetd.conf $format/etc-export/inetd.conf 2>/dev/null
else
  :
fi

#very 'rough' command to extract associated binaries from inetd.conf & show permisisons of each
inetdbinperms=`awk '{print $7}' /etc/inetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$inetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related inetd binary permissions:\e[00m\n$inetdbinperms"
  echo -e "\n"
else
  :
fi

xinetdread=`cat /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdread" ]; then
  echo -e "\e[00;31m[-] Contents of /etc/xinetd.conf:\e[00m\n$xinetdread"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$xinetdread" ]; then
  mkdir $format/etc-export/ 2>/dev/null
  cp /etc/xinetd.conf $format/etc-export/xinetd.conf 2>/dev/null
else
  :
fi

xinetdincd=`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null`
if [ "$xinetdincd" ]; then
  echo -e "\e[00;31m[-] /etc/xinetd.d is included in /etc/xinetd.conf - associated binary permissions are listed below:\e[00m"; ls -la /etc/xinetd.d 2>/dev/null
  echo -e "\n"
else
  :
fi

#very 'rough' command to extract associated binaries from xinetd.conf & show permisisons of each
xinetdbinperms=`awk '{print $7}' /etc/xinetd.conf 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$xinetdbinperms" ]; then
  echo -e "\e[00;31m[-] The related xinetd binary permissions:\e[00m\n$xinetdbinperms"
  echo -e "\n"
else
  :
fi

initdread=`ls -la /etc/init.d 2>/dev/null`
if [ "$initdread" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ binary permissions:\e[00m\n$initdread"
  echo -e "\n"
else
  :
fi

#init.d files NOT belonging to root!
initdperms=`find /etc/init.d/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initdperms" ]; then
  echo -e "\e[00;31m[-] /etc/init.d/ files not belonging to root (uid 0):\e[00m\n$initdperms"
  echo -e "\n"
else
  :
fi

rcdread=`ls -la /etc/rc.d/init.d 2>/dev/null`
if [ "$rcdread" ]; then
  echo -e "\e[00;31m[-] /etc/rc.d/init.d binary permissions:\e[00m\n$rcdread"
  echo -e "\n"
else
  :
fi

#init.d files NOT belonging to root!
rcdperms=`find /etc/rc.d/init.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$rcdperms" ]; then
  echo -e "\e[00;31m[-] /etc/rc.d/init.d files not belonging to root (uid 0):\e[00m\n$rcdperms"
  echo -e "\n"
else
  :
fi

usrrcdread=`ls -la /usr/local/etc/rc.d 2>/dev/null`
if [ "$usrrcdread" ]; then
  echo -e "\e[00;31m[-] /usr/local/etc/rc.d binary permissions:\e[00m\n$usrrcdread"
  echo -e "\n"
else
  :
fi

#rc.d files NOT belonging to root!
usrrcdperms=`find /usr/local/etc/rc.d \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$usrrcdperms" ]; then
  echo -e "\e[00;31m[-] /usr/local/etc/rc.d files not belonging to root (uid 0):\e[00m\n$usrrcdperms"
  echo -e "\n"
else
  :
fi

initread=`ls -la /etc/init/ 2>/dev/null`
if [ "$initread" ]; then
  echo -e "\e[00;31m[-] /etc/init/ config file permissions:\e[00m\n$initread"
  echo -e "\n"
else
  :
fi

# upstart scripts not belonging to root
initperms=`find /etc/init \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$initperms" ]; then
   echo -e "\e[00;31m[-] /etc/init/ config files not belonging to root:\e[00m\n$initperms"
   echo -e "\n"
else
  :
fi

systemdread=`ls -lthR /lib/systemd/ 2>/dev/null`
if [ "$systemdread" ]; then
  echo -e "\e[00;31m[-] /lib/systemd/* config file permissions:\e[00m\n$systemdread"
  echo -e "\n"
else
  :
fi

# systemd files not belonging to root
systemdperms=`find /lib/systemd/ \! -uid 0 -type f 2>/dev/null |xargs -r ls -la 2>/dev/null`
if [ "$systemdperms" ]; then
   echo -e "\e[00;31m[-] /lib/systemd/* config files not belonging to root:\e[00m\n$systemdperms"
   echo -e "\n"
else
  :
fi

}

#enum some rbash escape bins, sudo version
# check for dev tools (awk/perl/python/nc/etc)
# list installed packages
# ls -alh /usr/bin/
# ls -alh /sbin/
# dpkg -l
# rpm -qa
# ls -alh /var/cache/apt/archivesO
# ls -alh /var/cache/yum/
binary_search()
{
echo -e "\e[00;33m### Installed Binary Information ####################################\e[00m"

#checks to see if various files are installed
echo -e "\e[00;31mUseful file locations:\e[00m" ; which nc 2>/dev/null ; which netcat 2>/dev/null ; which wget 2>/dev/null ; which nmap 2>/dev/null ; which gcc 2>/dev/null ; which python 2>/dev/null
echo -e "\n"

#limited search for installed compilers
compiler=`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`
if [ "$compiler" ]; then
  echo -e "\e[00;31m[-] Installed compilers:\e[00m\n$compiler"
  echo -e "\n"
 else
  :
fi

whattosudo=`echo '' | sudo -l 2>/dev/null`
if [ "$whattosudo" ]; then
  echo -e "\e[00;33m[+] Can we run anything with sudo without a password? (sudo -l)\e[00m\n$whattosudo"
  echo -e "\n"
else
  :
fi

#known 'good' breakout binaries
#without authentication
sudopwnage=`echo '' | sudo -S -l -k 2>/dev/null | grep -iw 'ash\|awk\|bash\|busybox\|cpulimit\|crontab\|csh\|dash\|ed\|emacs\|env\|expect\|find\|flock\|ftp\|gdb\|git\|ionice\|ksh\|ld.so\|less\|ltrace\|lua\|mail\|make\|man\|more\|nano\|nice\|nmap\|node\|perl\|pg\|php\|pico\|puppet\|python2\|python3\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|scp\|sed\|setarch\|sftp\|sqlite3\|ssh\|stdbuf\|strace\|tar\|taskset\|tclsh\|tcpdump\|telnet\|time\|timeout\|unshare\|vi\|vim\|watch\|wish\|xargs\|zip\|zsh' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnage" ]; then
  echo -e "\e[00;33m[+] Possible Sudo PWNAGE! (interactive shell)\e[00m\n$sudopwnage"
  echo -e "\n"
else
  :
fi

sudopwnagemore=`echo '' | sudo -S -l -k 2>/dev/null | grep -iw 'ash\|awk\|base64\|bash\|busybox\|cat\|cpulimit\|crontab\|csh\|curl\|cut\|dash\|dd\|diff\|docker\|ed\|emacs\|env\|expand\|expect\|find\|flock\|fmt\|fold\|ftp\|gdb\|git\|head\|ionice\|jq\|ksh\|ld.so\|ltrace\|lua\|mail\|make\|man\|more\|mount\|nano\|nc\|nice\|nl\|nmap\|node\|od\|perl\|pg\|php\|pico\|puppet\|python2\|python3\|rlwrap\|rpm\|rpmquery\|rsync\|ruby\|scp\|sed\|setarch\|sftp\|socat\|sort\|sqlite3\|ssh\|stdbuf\|strace\|tail\|tar\|taskset\|tclsh\|tcpdump\|tee\|telnet\|tftp\|time\|timeout\|ul\|unexpand\|uniq\|unshare\|vi\|vim\|watch\|wget\|wish\|xargs\|xdd\|zip\|zsh' | xargs -r ls -la 2>/dev/null`
if [ "$sudopwnagemore" ]; then
  echo -e "\e[00;33m[+] Known abusable sudo binaries!\e[00m\n$sudopwnagemore"
  echo -e "\n"
else
  :
fi

##known 'good' breakout binaries (cleaned to parse /etc/sudoers for comma separated values) - authenticated
#with authentication
if [ "$sudopass" ]; then
    if [ "$sudoperms" ]; then
      :
    else
      sudopermscheck=`echo $userpassword | sudo -S -l -k 2>/dev/null | xargs -n 1 2>/dev/null|sed 's/,*$//g' 2>/dev/null | grep -w $binarylist 2>/dev/null`
      if [ "$sudopermscheck" ]; then
        echo -e "\e[00;33m[-] Possible sudo pwnage!\e[00m\n$sudopermscheck"
        echo -e "\n"
     else
        :
      fi
    fi
else
  :
fi

#sudo version - check to see if there are any known vulnerabilities with this
sudover=`sudo -V 2>/dev/null| grep "Sudo version" 2>/dev/null`
if [ "$sudover" ]; then
  echo -e "\e[00;31m[-] Sudo version:\e[00m\n$sudover"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $sudover >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#bash version checks
bashversion=`bash --version 2>/dev/null | grep "version" 2>/dev/null`
if [ "$bashversion" ]; then
  echo -e "\e[00;31m[-] Bash version:\e[00m\n$bashversion"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $bashversion >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#bash shellshock checks
shellshock=`x='() { :;}; echo VULNERABLE' bash -c :`
if [ "$shellshock" ]; then
  echo -e "\e[00;32m[+] Shellshock check : \e[00m\n$shellshock"
  echo -e "\n"
else
  :
fi

##Start Automation section##
#ansible
ansiblecmd=`which ansible 2>/dev/null`
if [ "$ansiblecmd" ]; then
  echo -e "\e[00;31m[-] Ansible automation software installed, it may be in use\e[00m\n$ansiblecmd"
  echo -e "\n"
else
  :
fi

#cfengine
cfenginecmd=`which cfagent 2>/dev/null`
if [ "$cfenginecmd" ]; then
  echo -e "\e[00;31m[-] CFEngine automation software installed, it may be in use\e[00m\n$cfenginecmd"
  echo -e "\n"
else
  :
fi

#chef
chefcmd=`which erchef 2>/dev/null`
if [ "$chefcmd" ]; then
  echo -e "\e[00;31m[-] Chef automation software installed, it may be in use\e[00m\n$chefcmd"
  echo -e "\n"
else
  :
fi

#puppet
puppetcmd=`which puppet 2>/dev/null`
if [ "$puppetcmd" ]; then
  echo -e "\e[00;31m[-] Puppet automation software installed, it may be in use\e[00m\n$puppetcmd"
  echo -e "\n"
else
  :
fi

##Start AV section##
#clamAV binary check
clamcmd=`which clamconf 2>/dev/null`
clamscancmd=`whichslamscan 2>/dev/null`
if [ "$clamcmd" -o "$clamscancmd" ]; then
  echo -e "\e[00;31m[-] ClamAV malware scanner installed, it may be in use\e[00m\n"
  if [ ! -z "$clamcsm" ]; then
    echo -e "[-] Clamconf: $clamconf\n"
  else
    :
  fi
  if [ ! -z "$clamscancmd" ]; then
    echo -e "[-] Clamscan: $clamscancmd\n"
  else
    :
  fi
else
  :
fi

#chkrootkit binary check
chkrootkitcmd=`which chkrootkit 2>/dev/null`
if [ "$chkrootkitcmd" ]; then
  echo -e "\e[00;31m[-] Chkrootkit malware scanner installed, it may be in use\e[00m\n$chkrootkitcmd"
  echo -e "\n"
else
  :
fi

#maldet binary check
malcmd=`which maldet 2>/dev/null`
if [ "$malcmd" ]; then
  echo -e "\e[00;31m[-] Maldet malware scanner installed, it may be in use\e[00m\n$malcdm"
  echo -e "\n"
else
  :
fi

#snort binary check
snortcmd=`which snort 2>/dev/null`
if [ "$snortcmd" ]; then
  echo -e "\e[00;31m[-] Snort IDS installed, it may be in use\e[00m\n$snortcmd"
  echo -e "\n"
else
  :
fi

#list all debian packages
if [ "$verinfo" = "1" ]; then
  echo -e "\e[00;31m[-] Writing all installed packages: dpkg -l:\e[00m\n"
  cmd=`dpkg --list 2>/dev/null | grep "^ii" | awk '{print $2 " " $3 " " $5}'`
  cmd2=`dpkg --list 2>/dev/null | grep "^ii" | awk '{print $2 " " $3}'`
  if [ "$cmd" ]; then
    # echo -e "Name                                        Version                          Description\n"
    # echo -e "$cmd"
    echo -e "\n"
    if [ "$verinfo" = "1" ]; then
      echo -e "$cmd2" >> verinfo.txt 2>/dev/null
    else
      :
    fi
  else
    :
  fi
fi

#list all RH/rpm packages
#rpm -qa #RHEL dpkg --list
if [ "$verinfo" = "1" ]; then
  echo -e "\e[00;31m[-] Writing all installed packages: rpm -qa:\e[00m\n"
  rpmcmd=`rpm -qa 2>/dev/null`
  if [ "$rpmcmd" ]; then
    # echo -e "$rpmcmd"
    echo -e "\n"
    if [ "$verinfo" = "1" ]; then
      echo -e $rpmcmd >> verinfo.txt 2>/dev/null
    else
      :
    fi
  else
    :
  fi
fi
}

os_protections()
{
echo -e "\e[00;33m### OS Protections and Binary Protection Information ####################################\e[00m"

#fail2ban
fail2bancmd=`which fail2ban 2>/dev/null`
fail2bancmd2=`which fail2ban-client 2>/dev/null`
if [ "$fail2bancmd" -o "$fail2bancmd2" ]; then
  fail2banconfigs=`cat /etc/fail2ban/jail.local 2>/dev/nul`
  fail2banconfigs2=`cat /etc/fail2ban/jail.conf`
  echo -e "\e[00;31m[-] jail.local config\e[00m\n$fail2banconfigs"
  echo -e "\n"
  echo -e "\e[00;31m[-] jail.conf config\e[00m\n$fail2banconfigs2"
  echo -e "\n"
else
  :
fi

#Solaris NX
nxcmd=`grep noexec_user_stack /etc/system 2>/dev/null | grep -v _log | grep 1`
if [ -z "$nxcmd" ]; then
  echo -e "\e[00;31m[-] Etc System No NX\e[00m\n$nxcmd"
  echo -e "\n"
else
  :
fi

#Solaris NXlog
nxlog=`grep noexec_user_stack_log /etc/system 2>/dev/null | grep 1`
if [ -z "$nxlog" ]; then
  echo -e "\e[00;31m[-] Etc System No NX Logging\e[00m\n$nxlog"
  echo -e "\n"
else
  :
fi

#Solaris Auditing
nxaudit=`grep c2audit:audit_load /etc/system 2>/dev/null |  grep 1`
if [ -z "$nsaudit" ]; then
  echo -e "\e[00;31m[-] Etc System No Auditing\e[00m\n$nxaudit"
  echo -e "\n"
else
  :
fi

#hpux NX
nxcmd2=`kmtune -q executable_stack 2>/dev/null | grep executable_stack | awk '{print $2}'`
if [ "$nxcmd2" = "1" ]; then
  echo -e "\e[00;31m[-] kmtune -q executable_stack No NX!\e[00m\n$nxcmd2"
  echo -e "\n"
elif [ "$nxcmd2" = "2" ]; then
  echo -e "\e[00;31m[-] kmtune -q executable_stack NX set to logging only!\e[00m\n$nxcmd2"
  echo -e "\n"
else
  :
fi

#linux ASLR
aslrcmd=`sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}'`
if [ "$aslrcmd" = "0" ]; then
  echo -e "\e[00;31m[-] sysctl kernel.randomize_va_space No NX\e[00m\n$aslrcmd"
  echo -e "\n"
elif [ "$aslrcmd" = "1" ]; then
  echo -e "\e[00;31m[-] sysctl kernel.randomize_va_space Conservative ASLR\e[00m\n$aslrcmd"
  echo -e "\n"
else
  :
fi

#linux mmap
mmapcmd=`cat /proc/sys/vm/mmap_min_addr 2>/dev/null`
if [ "$mmapcmd" = "0" -o "$mmapcmd" = "" ]; then
  echo -e "\e[00;31m[-] Cat Proc/sys/vm/mmap_min_addr allows map to 0\e[00m\n$mmapcmd"
  echo -e "\n"
else
  :
fi

#linux se linux
if [ ! -f /selinux/enforce ]; then
  echo -e "\e[00;31m[-] Selinux/enforce, SELinux does not enforce\e[00m"
  echo -e "\n"
else
  :
fi

#Identify programs and gather some specific stats
echo -e "\e[00;31m[-] Processes, their directories, and possible protections\e[00m"
for PROCDIR in /proc/[0-9]*; do
  unset PROGPATH
  PID=`echo $PROCDIR | cut -f 3 -d /`
  echo ------------------------
  echo "PID:           $PID"
  if [ -d "$PROCDIR" ]; then
    if [ -r "$PROCDIR/exe" ]; then
      PROGPATH=`ls -l "$PROCDIR/exe" 2>&1 | sed 's/ (deleted)//' | awk '{print $NF}'`
    else
      if [ -r "$PROCDIR/cmdline" ]; then
	      P=`cat $PROCDIR/cmdline | tr "\0" = | cut -f 1 -d = | grep '^/'`
        if [ -z "$P" ]; then
          echo "ERROR: Can't find full path of running program: "`cat $PROCDIR/cmdline`
        else
          PROGPATH=$P
        fi
      else
        echo "ERROR: Can't find full path of running program: "`cat $PROCDIR/cmdline`
        continue
      fi
    fi
  else
    echo "ERROR: Can't find full path of running process.  Process has gone."
    continue
  fi
  if [ -n "$PROGPATH" ]; then
    echo "Program path: $PROGPATH"
    NX=`grep stack $PROCDIR/maps 2>/dev/null | grep -v "rw-"`
    if [ -n "$NX" ]; then
      echo "[UPC040] WARNING: NX not enabled"
    fi

    SSP=`objdump -D $PROCDIR/exe 2>/dev/null | grep stack_chk`
    if [ -z "$SSP" ]; then
      echo "[UPC041] WARNING: SSP not enabled or objdump not installed"
    fi
  fi
done

}

####APACHE########www####
# apache --version, apache invokee, apache modules, /etc/apache2/apache2.conf
# /etc/httpd/conf/httpd.conf
# ls -alhR /var/www/, ls -alhR /srv/www/htdocs/, ls -alhR /usr/local/www/apache22/data/
# ls -alhR /opt/lampp/htdocs/, ls -alhR /var/www/html/
apache_enum()
{
echo -e "\e[00;33m### Apache Information ####################################\e[00m"

#apache details - if installed
apachever=`apache2 -v 2>/dev/null; httpd -v 2>/dev/null;`
if [ "$apachever" ]; then
  echo -e "\e[00;31m[-] Apache version:\e[00m\n$apachever"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $apachever >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#what account is apache running under
apacheusr=`grep -i 'user\|group' /etc/apache2/envvars 2>/dev/null |awk '{sub(/.*\export /,"")}1' 2>/dev/null`
if [ "$apacheusr" ]; then
  echo -e "\e[00;31m[-] Apache user configuration:\e[00m\n$apacheusr"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$apacheusr" ]; then
  mkdir --parents $format/etc-export/apache2/ 2>/dev/null
  cp /etc/apache2/envvars $format/etc-export/apache2/envvars 2>/dev/null
else
  :
fi

#installed apache modules
apachemodules=`apache2ctl -M 2>/dev/null; httpd -M 2>/dev/null`
if [ "$apachemodules" ]; then
  echo -e "\e[00;31m[-] Installed Apache modules:\e[00m\n$apachemodules"
  echo -e "\n"
else
  :
fi

#anything in the default http home dirs (changed to thorough as can be large)
if [ "$thorough" = "1" ]; then
  apachehomedirs=`ls -alhR /var/www/ 2>/dev/null; ls -alhR /srv/www/htdocs/ 2>/dev/null; ls -alhR /usr/local/www/apache2/data/ 2>/dev/null; ls -alhR /opt/lampp/htdocs/ 2>/dev/null`
  if [ "$apachehomedirs" ]; then
    echo -e "\e[00;31m[-] www home dir contents:\e[00m\n$apachehomedirs"
    echo -e "\n"
else
    :
  fi
fi

#htpasswd check
htpasswd=`find / -name .htpasswd -print -exec cat {} \; 2>/dev/null`
if [ "$htpasswd" ]; then
    echo -e "\e[00;33m[+] htpasswd found - could contain passwords:\e[00m\n$htpasswd"
    echo -e "\n"
else
    :
fi
}

nginx_enum()
{
nginxbin=`which nginx 2>/dev/null`
if [ "$nginxbin" ]; then
  echo -e "\e[00;31m[-] Nginx bin installed, it may be in use\e[00m\n$nginxbin"
  echo -e "\n"
else
  :
fi

nginxconf=`find /etc/ -name nginx.conf -type f 2>/dev/null`
nginxconfalt=`find /usr/local/ -name nginx.conf -type f 2>/dev/null`
if [ "$nginxconf" ]; then
  catconf=`cat "$nginxconf" 2>/dev/null`
  echo -e "\e[00;31m[-] Etc nginx.conf\e[00m\n$nginxconf\n$catconf"
  echo -e "\n"
elif [ "$nginxconfalt" ]; then
  catconf=`cat "$nginxconfalt" 2>/dev/null`
  echo -e "\e[00;31m[-] Usr local nginx.conf\e[00m\n$nginxconfalt\n$catconf"
  echo -e "\n"
else
  :
fi
}

mysql_enum()
{
echo -e "\e[00;33m### MySQL Information ####################################\e[00m"

#mysql details - if installed
mysqlver=`mysql --version 2>/dev/null`
if [ "$mysqlver" ]; then
  echo -e "\e[00;31m[-] MYSQL version:\e[00m\n$mysqlver"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $mysqlver >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#checks to see if root/root will get us a connection
mysqlconnect=`mysqladmin -uroot -proot version 2>/dev/null`
mysqlconnect2=`mysql -uroot -proot version 2>/dev/null`
if [ "$mysqlconnect" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect"
  echo -e "\n"
elif [ "$mysqlconnect2" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with default root/root credentials!\e[00m\n$mysqlconnect2"
  echo -e "\n"
else
  :
fi

#check to see if root can connect without a password
mysqlconnect3=`mysqladmin -uroot --password= version 2>/dev/null`
mysqlconnect4=`mysql -uroot --password= version 2>/dev/null`
if [ "$mysqlconnect3" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with root and NO password!\e[00m\n$mysqlconnect3"
  echo -e "\n"
elif [ "$mysqlconnect4" ]; then
  echo -e "\e[00;33m[+] We can connect to the local MYSQL service with root and NO password!\e[00m\n$mysqlconnect4"
  echo -e "\n"
else
  :
fi
}

mongo_enum()
{
#check for install #TODO make this better, check for service instead
mongodbinstalled=`which mongodb 2>/dev/null`
if [ "$mongodbinstalled" ]; then
  echo -e "\e[00;31m[-] MongoDB installed at:\e[00m\n$mongodbinstalled"
  echo -e "\n"
else
  :
fi
}

####POSTGRES####
# postgres --version
#!!postgres default login
#!!trust relationships
#!!verify trust relationships
#!!check permissions of postgres config file #default login
postgres_enum()
{
echo -e "\e[00;33m### Postgres Information ####################################\e[00m"

#postgres details - if installed
postgver=`psql -V 2>/dev/null`
if [ "$postgver" ]; then
  echo -e "\e[00;31m[-] Postgres version:\e[00m\n$postgver"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $postgver >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#checks to see if any postgres password exists and connects to DB 'template0' - following commands are a variant on this
postcon1=`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon1" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'postgres' with no password!:\e[00m\n$postcon1"
  echo -e "\n"
else
  :
fi

postcon11=`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon11" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'postgres' with no password!:\e[00m\n$postcon11"
  echo -e "\n"
else
  :
fi

postcon2=`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon2" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template0' as user 'psql' with no password!:\e[00m\n$postcon2"
  echo -e "\n"
else
  :
fi

postcon22=`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`
if [ "$postcon22" ]; then
  echo -e "\e[00;33m[+] We can connect to Postgres DB 'template1' as user 'psql' with no password!:\e[00m\n$postcon22"
  echo -e "\n"
else
  :
fi
}

software_configs()
{
echo -e "\e[00;33m### SOFTWARE #############################################\e[00m"
}

interesting_files()
{
echo -e "\e[00;33m### INTERESTING FILES ####################################\e[00m"

#Specifically check to see if any user home dir has a gnupg folder for lax permissions
gpgfolder=`find /home -name "*.gnupg" -type d -exec ls -la {} \; 2>/dev/null`
if [ "$gpgfolder" ]; then
  echo -e "\e[00;31m[-] gnupg folder found in a user's home dir. Check for lax permissions and accessible keys!:\e[00m\n$gpgfolder"
  echo -e "\n"
else
  :
fi

#are any .plan files accessible in /home (could contain useful information)
usrplan=`find /home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$usrplan" ]; then
  echo -e "\e[00;31m[-] Plan file permissions and contents:\e[00m\n$usrplan"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$usrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $usrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else
  :
fi

bsdusrplan=`find /usr/home -iname *.plan -exec ls -la {} \; -exec cat {} 2>/dev/null \;`
if [ "$bsdusrplan" ]; then
  echo -e "\e[00;31m[-] Plan file permissions and contents:\e[00m\n$bsdusrplan"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$bsdusrplan" ]; then
  mkdir $format/plan_files/ 2>/dev/null
  for i in $bsdusrplan; do cp --parents $i $format/plan_files/; done 2>/dev/null
else
  :
fi

#are there any .rhosts files accessible - these may allow us to login as another user etc.
rhostsusr=`find /home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostsusr" ]; then
  echo -e "\e[00;33m[+] host config file(s) and file contents:\e[00m\n$rhostsusr"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$rhostsusr" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

bsdrhostsusr=`find /usr/home -iname *.rhosts -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$bsdrhostsusr" ]; then
  echo -e "\e[00;33m[+] host config file(s) and file contents:\e[00m\n$bsdrhostsusr"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$bsdrhostsusr" ]; then
  mkdir $format/rhosts 2>/dev/null
  for i in $bsdrhostsusr; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

rhostssys=`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} 2>/dev/null \;`
if [ "$rhostssys" ]; then
  echo -e "\e[00;33m[+] Hosts.equiv file details and file contents: \e[00m\n$rhostssys"
  echo -e "\n"
  else
  :
fi

if [ "$export" ] && [ "$rhostssys" ]; then
  mkdir $format/rhosts/ 2>/dev/null
  for i in $rhostssys; do cp --parents $i $format/rhosts/; done 2>/dev/null
else
  :
fi

#use supplied keyword and cat *.conf files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.conf files as no keyword was entered\n"
  else
    confkey=`find / -maxdepth 4 -name *.conf -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$confkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$confkey"
      echo -e "\n"
     else
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .conf files (recursive 4 levels):\e[00m"
	echo -e "'$keyword' not found in any .conf files"
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$confkey" ]; then
	  confkeyfile=`find / -maxdepth 4 -name *.conf -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/config_files/ 2>/dev/null
      for i in $confkeyfile; do cp --parents $i $format/keyword_file_matches/config_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#use supplied keyword and cat *.php files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search *.php files as no keyword was entered\n"
  else
    phpkey=`find / -maxdepth 10 -name *.php -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$phpkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels - output format filepath:identified line number where keyword appears):\e[00m\n$phpkey"
      echo -e "\n"
     else
  echo -e "\e[00;31m[-] Find keyword ($keyword) in .php files (recursive 10 levels):\e[00m"
  echo -e "'$keyword' not found in any .php files"
  echo -e "\n"
    fi
fi

if [ "$keyword" = "" ]; then
  :
  else
    if [ "$export" ] && [ "$phpkey" ]; then
    phpkeyfile=`find / -maxdepth 10 -name *.php -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/php_files/ 2>/dev/null
      for i in $phpkeyfile; do cp --parents $i $format/keyword_file_matches/php_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#use supplied keyword and cat *.log files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.log files as no keyword was entered\n"
  else
    logkey=`find / -name *.log -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$logkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (output format filepath:identified line number where keyword appears):\e[00m\n$logkey"
      echo -e "\n"
     else
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .log files (recursive 2 levels):\e[00m"
	echo -e "'$keyword' not found in any .log files"
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$logkey" ]; then
      logkeyfile=`find / -name *.log -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
	  mkdir --parents $format/keyword_file_matches/log_files/ 2>/dev/null
      for i in $logkeyfile; do cp --parents $i $format/keyword_file_matches/log_files/ ; done 2>/dev/null
    else
      :
  fi
fi

#use supplied keyword and cat *.ini files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ];then
  echo -e "[-] Can't search *.ini files as no keyword was entered\n"
  else
    inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$inikey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 4 levels - output format filepath:identified line number where keyword appears):\e[00m\n$inikey"
      echo -e "\n"
     else
	echo -e "\e[00;31m[-] Find keyword ($keyword) in .ini files (recursive 2 levels):\e[00m"
	echo -e "'$keyword' not found in any .ini files"
	echo -e "\n"
    fi
fi

if [ "$keyword" = "" ];then
  :
  else
    if [ "$export" ] && [ "$inikey" ]; then
	  inikey=`find / -maxdepth 4 -name *.ini -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
      mkdir --parents $format/keyword_file_matches/ini_files/ 2>/dev/null
      for i in $inikey; do cp --parents $i $format/keyword_file_matches/ini_files/ ; done 2>/dev/null
    else
      :
  fi
fi


#use supplied keyword and cat /var/www* files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search /var/www files as no keyword was entered\n"
else
  if [ -d "/var/www/" ]; then
    wwwkey=`find /var/www -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$wwwkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in /var/www files (output format filepath:identified line number where keyword appears):\e[00m\n$wwwkey"
      echo -e "\n"
    else
     echo -e "\e[00;31m[-] Find keyword ($keyword) in /var/www files:\e[00m"
     echo -e "'$keyword' not found in any /var/www files"
     echo -e "\n"
    fi
  fi
fi

if [ "$keyword" = "" ]; then
  :
else
  if [ "$export" ] && [ "$wwwkey" ]; then
    wwwkey=`find /var/www -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
    mkdir --parents $format/keyword_file_matches/www_files/ 2>/dev/null
    for i in $inikey; do cp --parents $i $format/keyword_file_matches/www_files/ ; done 2>/dev/null
  else
    :
  fi
fi

#use supplied keyword and cat /home/.* files for potential matches - output will show line number within relevant file path where a match has been located
if [ "$keyword" = "" ]; then
  echo -e "[-] Can't search /home/.* files as no keyword was entered\n"
else
  if [ -d "/home" ]; then
    hiddenkey=`find /home -name ".*" -type f -exec grep -Hn $keyword {} \; 2>/dev/null`
    if [ "$hiddenkey" ]; then
      echo -e "\e[00;31m[-] Find keyword ($keyword) in /home/.* files (output format filepath:identified line number where keyword appears):\e[00m\n$hiddenkey"
      echo -e "\n"
    else
     echo -e "\e[00;31m[-] Find keyword ($keyword) in /home/.* files:\e[00m"
     echo -e "'$keyword' not found in any /home/.* files"
     echo -e "\n"
    fi
  fi
fi

if [ "$keyword" = "" ]; then
  :
else
  if [ "$export" ] && [ "$hiddenkey" ]; then
    hiddenkey=`find /home -name ".*" -type f -exec grep -lHn $keyword {} \; 2>/dev/null`
    mkdir --parents $format/keyword_file_matches/home_files/ 2>/dev/null
    for i in $inikey; do cp --parents $i $format/keyword_file_matches/home_files/ ; done 2>/dev/null
  else
    :
  fi
fi

#quick extract of .conf files from /etc - only 1 level
allconf=`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} \; 2>/dev/null`
if [ "$allconf" ]; then
  echo -e "\e[00;31m[-] All *.conf files in /etc (recursive 1 level):\e[00m\n$allconf"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$allconf" ]; then
  mkdir $format/conf-files/ 2>/dev/null
  for i in $allconf; do cp --parents $i $format/conf-files/; done 2>/dev/null
else
  :
fi

#find all jar files, these may be interesting executables
alljars=`find / -name *.jar -type f -exec ls -la {} \; 2>/dev/null`
if [ "$alljars" ]; then
  echo -e "\e[00;31mAll .jar files. These may be exec or can be decompiled for potentially interesting information:\e[00m\n$alljars"
  echo -e "\n"
else
  :
fi

#extract any user history files that are accessible
usrhist=`ls -la ~/.*_history 2>/dev/null`
if [ "$usrhist" ]; then
  echo -e "\e[00;31m[-] Current user's history files:\e[00m\n$usrhist"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$usrhist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  for i in $usrhist; do cp --parents $i $format/history_files/; done 2>/dev/null
 else
  :
fi

#can we read roots *_history files - could be passwords stored etc.
roothist=`ls -la /root/.*_history 2>/dev/null`
if [ "$roothist" ]; then
  echo -e "\e[00;33m[+] Root's history files are accessible!\e[00m\n$roothist"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$roothist" ]; then
  mkdir $format/history_files/ 2>/dev/null
  cp $roothist $format/history_files/ 2>/dev/null
else
  :
fi

#all accessible .bash_history files in /home
checkbashhist=`find /home -name .bash_history -print -exec cat {} 2>/dev/null \;`
if [ "$checkbashhist" ]; then
  echo -e "\e[00;31m[-] Location and contents (if accessible) of .bash_history file(s):\e[00m\n$checkbashhist"
  echo -e "\n"
else
  :
fi

#is there any mail accessible
readmail=`ls -la /var/mail/ 2>/dev/null`
if [ "$readmail" ]; then
  echo -e "\e[00;31m[-] Any interesting mail in /var/mail:\e[00m\n$readmail"
  echo -e "\n"
else
  :
fi

#can we read roots mail
readmailroot=`head /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  echo -e "\e[00;33m[+] We can read /var/mail/root! (snippet below)\e[00m\n$readmailroot"
  echo -e "\n"
else
  :
fi

if [ "$export" ] && [ "$readmailroot" ]; then
  mkdir $format/mail-from-root/ 2>/dev/null
  cp $readmailroot $format/mail-from-root/ 2>/dev/null
else
  :
fi

#lets grab interesting log files
if [ "$thorough" = "1" ]; then
  logfiles=`find / -name *.log -type f -exec ls -lah {} \; 2>/dev/null`
  if [ "$logfiles" ]; then
    echo -e "\e[00;31m[-] Log files identified:\e[00m\n$logfiles"
    echo -e "\n"
  else
    :
  fi
else
  :
fi

if [ "$export" ] && [ "$logfiles" ]; then
  mkdir $format/log-files/ 2>/dev/null
    for i in $logfiles; do cp --parents $i $format/log-files/ ; done 2>/dev/null
else
  :
fi
}

####DOCKER####
# check if in a docker container
# check if in a docket host
# check if in a docker group
# check for docker files
docker_checks()
{
echo -e "\e[00;33m### Docker Checks ####################################\e[00m"

#specific checks - check to see if we're in a docker container
dockercontainer=` grep -i docker /proc/self/cgroup  2>/dev/null; find / -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
if [ "$dockercontainer" ]; then
  echo -e "\e[00;33m[+] Looks like we're in a Docker container:\e[00m\n$dockercontainer"
  echo -e "\n"
else
  :
fi

#specific checks - check to see if we're a docker host
dockerhost=`docker --version 2>/dev/null; docker ps -a 2>/dev/null`
if [ "$dockerhost" ]; then
  echo -e "\e[00;33m[+] Looks like we're hosting Docker:\e[00m\n$dockerhost"
  echo -e "\n"
  if [ "$verinfo" = "1" ]; then
    echo -e $dockerhost >> verinfo.txt 2>/dev/null
  else
    :
  fi
else
  :
fi

#specific checks - are we a member of the docker group
dockergrp=`id | grep -i docker 2>/dev/null`
if [ "$dockergrp" ]; then
  echo -e "\e[00;33m[+] We're a member of the (docker) group - could possibly misuse these rights!:\e[00m\n$dockergrp"
  echo -e "\n"
else
  :
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} 2>/dev/null \;`
if [ "$dockerfiles" ]; then
  echo -e "\e[00;31m[-] Anything juicy in the Dockerfile?:\e[00m\n$dockerfiles"
  echo -e "\n"
else
  :
fi

#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} 2>/dev/null \;`
if [ "$dockeryml" ]; then
  echo -e "\e[00;31m[-] Anything juicy in docker-compose.yml?:\e[00m\n$dockeryml"
  echo -e "\n"
else
  :
fi
}

lxc_container_checks()
{
echo -e "\e[00;33m### LXC Container Checks ####################################\e[00m"

  #specific checks - are we in an lxd/lxc container
  lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
  if [ "$lxccontainer" ]; then
    echo -e "\e[00;33m[+] Looks like we're in a lxc container:\e[00m\n$lxccontainer"
    echo -e "\n"
  fi

  #specific checks - are we a member of the lxd group
  lxdgroup=`id | grep -i lxd 2>/dev/null`
  if [ "$lxdgroup" ]; then
    echo -e "\e[00;33m[+] We're a member of the (lxd) group - could possibly misuse these rights!:\e[00m\n$lxdgroup"
    echo -e "\n"
  fi
}

footer()
{
echo -e "\e[00;33m### SCAN COMPLETE ####################################\e[00m"
}

call_each()
{
  header
  debug_info
  system_info
  user_info
  environmental_info
  users_and_groups
  quick_passwd_wins
  home_and_user_files
  authentication_information
  ssh_enum
  mount_information
  special_perm_files
  executable_files_folders
  writeable_files_folders
  readable_files_folders
  job_info
  networking_info
  services_info
  binary_search
  os_protections
  apache_enum
  nginx_enum
  mysql_enum
  mongo_enum
  postgres_enum
  software_configs
  interesting_files
  docker_checks
  lxc_container_checks
  footer
}

while getopts "h:v:k:r:e:i:s:t" option; do
 case "${option}" in
    k) keyword=${OPTARG};;
    r) report=${OPTARG}"-"`date +"%d-%m-%y"`;;
    e) export=${OPTARG};;
    i) verinfo=1;;
    s) sudopass=1;;
    t) thorough=1;;
    v) header; exit;;
    h) usage; exit;;
    *) usage; exit;;
 esac
done

call_each | tee -a $report 2> /dev/null
#EndOfScript

#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
Copyright (c) 2014 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys, os
from PyQt4 import QtCore, QtGui
from app.auxiliary import *												# for timestamp

#makedir function from https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
#Compatible with Python >2.5, but there is a more advanced function for python 3.5
def mkdir_p(path):
	try:
		os.makedirs(path)
	except OSError as exc: #Python >2.5
		if exc.errno == errno.EEXIST and os.path.isdir(path):
			pass
		else:
			raise
#Create the directories that are currently hardcoded in the script
#dotdotpwn directory for reports created automatically by dotdotpwn just in case user wants them
def createDirectories():
	scriptsToRun = "dirb","dirb/80","dirb/443","dotdotpwn","finger","ftp","http","ldap","msrpc","mssql","mysql","nfs","nikto","nmap","rdp","rpc","smb","smtp","snmp","ssh","telnet","tftp","whatweb"
	for path in scriptsToRun:
		mkdir_p("/root/scripts/recon_enum/results/exam/%s" % path)
	mkdir_p("/usr/share/dotdotpwn/Reports")

def backupExisting():
	print "INFO: Previous folders found, zipping backup"
    #tmp move targets.txt, zip files, backup, remove dirs, restore targets.txt
	movedTargets = False
	movedDotTemplate = False
	if os.path.isfile("/root/scripts/recon_enum/results/exam/targets.txt"):
		os.rename("/root/scripts/recon_enum/results/exam/targets.txt", "/root/scripts/recon_enum/results/targets.txt")
		movedTargets = True
	if os.path.isfile("/root/scripts/recon_enum/results/exam/dot_template"):
		os.rename("/root/scripts/recon_enum/results/exam/dot_template", "/root/scripts/recon_enum/results/dot_template")
		movedDotTemplate = True
	backupName = "backup_%s.tar.gz" % (time.strftime("%H:%M"))
	BACKUP = "tar czf /root/Downloads/%s /root/scripts/recon_enum/results/exam/* --remove-files" % (backupName)
	backupResults = subprocess.check_output(BACKUP, shell=True)
	if movedTargets == True:
		os.rename("/root/scripts/recon_enum/results/targets.txt", "/root/scripts/recon_enum/results/exam/targets.txt")
	if movedDotTemplate == True:
		os.rename("/root/scripts/recon_enum/results/dot_template", "/root/scripts/recon_enum/results/exam/dot_template")

#Symlink needed directories into /usr/share/wordlists
#This functionality for a distro like Kali
#Wordlists folder used for ftp and ssh recon scripts
def mksymlink():
	dirsToLink = "/root/lists","/root/lists/SecLists-master"
	dst = "/usr/share/wordlists"
	for path in dirsToLink:
		tmp = path.split("/")
		try:
			os.symlink(path, dst + "/" + tmp[-1])
		except OSError as exc:
			if exc.errno == errno.EEXIST:
				pass
			else:
				raise

# this class reads and writes application settings
class AppSettings():
	def __init__(self):
		# check if settings file exists and creates it if it doesn't
		if not os.path.exists('./sparta.conf'):
			print '[+] Creating settings file..'
			self.createDefaultSettings()
		else:
			print '[+] Loading settings file..'
			mksymlink()
			if os.path.isdir('/root/scripts/recon_enum/results/exam/nmap'):
				print 'Ready ReconScan'
				backupExisting()
				createDirectories()
			if not os.path.isdir('/root/scripts/recon_enum/results/exam/nmap'):
				createDirectories()
			self.actions = QtCore.QSettings('./sparta.conf', QtCore.QSettings.NativeFormat)

	# This function creates the default settings file. Note that, in general, everything is case sensitive.
	# Each action should be in the following format:
	#
	# (key, [label, command, service])
	# key 		- must be unique within the group and is used to retrieve each action. is used to create the tab titles and also to recognise nmap commands so we can parse the output (case sensitive)
	# label 	- is what appears in the context menu in the gui
	# command	- command that will be run. These placeholders will be replaced on-the-fly:	[IP] [PORT] [OUTPUT]
	# service	- service(s) to which the tool applies (comma-separated). Leave empty if valid for all services.
	def createDefaultSettings(self):
		self.actions = QtCore.QSettings('./sparta.conf', QtCore.QSettings.NativeFormat)

		self.actions.beginGroup('GeneralSettings')
		self.actions.setValue('default-terminal','gnome-terminal')
		self.actions.setValue('tool-output-black-background','False')
		self.actions.setValue('screenshooter-timeout','15000')
		self.actions.setValue('web-services','http,https,ssl,soap,http-proxy,http-alt,https-alt')
		self.actions.setValue('enable-scheduler','True')
		self.actions.setValue('enable-scheduler-on-import','False')
		self.actions.setValue('max-fast-processes', '10')
		self.actions.setValue('max-slow-processes', '10')
		self.actions.endGroup()

		self.actions.beginGroup('BruteSettings')
		self.actions.setValue('store-cleartext-passwords-on-exit','True')
		self.actions.setValue('username-wordlist-path','/usr/share/wordlists/')
		self.actions.setValue('password-wordlist-path','/usr/share/wordlists/')
		self.actions.setValue('default-username','root')
		self.actions.setValue('default-password','password')
		self.actions.setValue('services', "asterisk,afp,cisco,cisco-enable,cvs,firebird,ftp,ftps,http-head,http-get,https-head,https-get,http-get-form,http-post-form,https-get-form,https-post-form,http-proxy,http-proxy-urlenum,icq,imap,imaps,irc,ldap2,ldap2s,ldap3,ldap3s,ldap3-crammd5,ldap3-crammd5s,ldap3-digestmd5,ldap3-digestmd5s,mssql,mysql,ncp,nntp,oracle-listener,oracle-sid,pcanywhere,pcnfs,pop3,pop3s,postgres,rdp,rexec,rlogin,rsh,s7-300,sip,smb,smtp,smtps,smtp-enum,snmp,socks5,ssh,sshkey,svn,teamspeak,telnet,telnets,vmauthd,vnc,xmpp")
		self.actions.setValue('no-username-services', "cisco,cisco-enable,oracle-listener,s7-300,snmp,vnc")
		self.actions.setValue('no-password-services', "oracle-sid,rsh,smtp-enum")
		self.actions.endGroup()

		self.actions.beginGroup('StagedNmapSettings')
		self.actions.setValue('stage1-ports','T:80,443')
		self.actions.setValue('stage2-ports','T:25,135,137,139,445,1433,3306,5432,U:137,161,162,1434')
		self.actions.setValue('stage3-ports','T:23,21,22,110,111,2049,3389,8080,U:500,5060')
		self.actions.setValue('stage4-ports','T:0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048,2050-3305,3307-3388,3390-5431,5433-8079,8081-29999')
		self.actions.setValue('stage5-ports','T:30000-65535')
		self.actions.endGroup()

		self.actions.beginGroup('ToolSettings')
		self.actions.setValue('nmap-path','/usr/bin/nmap')
		self.actions.setValue('hydra-path','/usr/bin/hydra')
		self.actions.setValue('cutycapt-path','/usr/bin/cutycapt')
		self.actions.setValue('texteditor-path','/usr/bin/leafpad')
		self.actions.endGroup()

		self.actions.beginGroup('HostActions')
		self.actions.setValue("nmap-fast-tcp", ["Run nmap (fast TCP)", "nmap -Pn -F -T4 -vvvv [IP] -oA \"[OUTPUT]\""])
		self.actions.setValue("nmap-full-tcp", ["Run nmap (full TCP)", "nmap -Pn -sV -sC -O -p- -T4 -vvvvv [IP] -oA \"[OUTPUT]\""])
		self.actions.setValue("nmap-fast-udp", ["Run nmap (fast UDP)", "nmap -n -Pn -sU -F --min-rate=1000 -vvvvv [IP] -oA \"[OUTPUT]\""])
		self.actions.setValue("nmap-udp-1000", ["Run nmap (top 1000 quick UDP)", "nmap -n -Pn -sU --min-rate=1000 -vvvvv [IP] -oA \"[OUTPUT]\""])
		self.actions.setValue("nmap-full-udp", ["Run nmap (full UDP)", "nmap -n -Pn -sU -p- -T4 -vvvvv [IP] -oA \"[OUTPUT]\""])
		self.actions.setValue("unicornscan-full-udp", ["Run unicornscan (full UDP)", "unicornscan -mU -Ir 1000 [IP]:a -v"])
		self.actions.endGroup()

		self.actions.beginGroup('PortActions')
		self.actions.setValue("banner", ["Grab banner", "bash -c \"echo \"\" | nc -v -n -w1 [IP] [PORT]\"", ""])
		self.actions.setValue("nmap", ["Run nmap (scripts) on port", "nmap -Pn -sV -sC -vvvvv -p[PORT] [IP] -oA [OUTPUT]", ""])
		self.actions.setValue("nikto", ["Run nikto", "nikto -o \"[OUTPUT].txt\" -p [PORT] -h [IP]", "http,https,ssl,soap,http-proxy,http-alt"])
		self.actions.setValue("dirbuster", ["Launch dirbuster", "java -Xmx256M -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar -u http://[IP]:[PORT]/", "http,https,ssl,soap,http-proxy,http-alt"])
		self.actions.setValue("webslayer", ["Launch webslayer", "webslayer", "http,https,ssl,soap,http-proxy,http-alt"])
		self.actions.setValue("whatweb", ["Run whatweb", "whatweb [IP]:[PORT] --color=never --log-brief=\"[OUTPUT].txt\"", "http,https,ssl,soap,http-proxy,http-alt"])

		### SMB
		self.actions.setValue("samrdump", ["Run samrdump", "python /usr/share/doc/python-impacket/examples/samrdump.py [IP] [PORT]/SMB", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("nbtscan", ["Run nbtscan", "nbtscan -v -h [IP]", "netbios-ns"])
		self.actions.setValue("smbenum", ["Run smbenum", "bash ./scripts/smbenum.sh [IP]", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("enum4linux", ["Run enum4linux", "enum4linux [IP]", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("polenum", ["Extract password policy (polenum)", "polenum [IP]", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-users", ["Enumerate users (nmap)", "nmap -p[PORT] --script=smb-enum-users [IP] -vvvvv", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-users-rpc", ["Enumerate users (rpcclient)", "bash -c \"echo 'enumdomusers' | rpcclient [IP] -U%\"", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-admins", ["Enumerate domain admins (net)", "net rpc group members \"Domain Admins\" -I [IP] -U% ", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-groups", ["Enumerate groups (nmap)", "nmap -p[PORT] --script=smb-enum-groups [IP] -vvvvv", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-shares", ["Enumerate shares (nmap)", "nmap -p[PORT] --script=smb-enum-shares [IP] -vvvvv", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-sessions", ["Enumerate logged in users (nmap)", "nmap -p[PORT] --script=smb-enum-sessions [IP] -vvvvv", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-enum-policies", ["Extract password policy (nmap)", "nmap -p[PORT] --script=smb-enum-domains [IP] -vvvvv", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("smb-null-sessions", ["Check for null sessions (rpcclient)", "bash -c \"echo 'srvinfo' | rpcclient [IP] -U%\"", "netbios-ssn,microsoft-ds"])
		###

		self.actions.setValue("ldapsearch", ["Run ldapsearch", "ldapsearch -h [IP] -p [PORT] -x -s base", "ldap"])
		self.actions.setValue("snmpcheck", ["Run snmpcheck", "snmp-check -t [IP]", "snmp,snmptrap"])    ###Change from snmpcheck to snmp-check for Kali 2.0
		self.actions.setValue("rpcinfo", ["Run rpcinfo", "rpcinfo -p [IP]", "rpcbind"])
		self.actions.setValue("rdp-sec-check", ["Run rdp-sec-check.pl", "perl ./scripts/rdp-sec-check.pl [IP]:[PORT]", "ms-wbt-server"])
		self.actions.setValue("showmount", ["Show nfs shares", "showmount -e [IP]", "nfs"])
		self.actions.setValue("x11screen", ["Run x11screenshot", "bash ./scripts/x11screenshot.sh [IP]", "X11"])
		self.actions.setValue("sslscan", ["Run sslscan", "sslscan --no-failed [IP]:[PORT]", "https,ssl"])
		self.actions.setValue("sslyze", ["Run sslyze", "sslyze --regular [IP]:[PORT]", "https,ssl,ms-wbt-server,imap,pop3,smtp"])

		self.actions.setValue("rwho", ["Run rwho", "rwho -a [IP]", "who"])
		self.actions.setValue("finger", ["Enumerate users (finger)", "./scripts/fingertool.sh [IP]", "finger"])

		self.actions.setValue("smtp-enum-vrfy", ["Enumerate SMTP users (VRFY)", "smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t [IP] -p [PORT]", "smtp"])
		self.actions.setValue("smtp-enum-expn", ["Enumerate SMTP users (EXPN)", "smtp-user-enum -M EXPN -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t [IP] -p [PORT]", "smtp"])
		self.actions.setValue("smtp-enum-rcpt", ["Enumerate SMTP users (RCPT)", "smtp-user-enum -M RCPT -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t [IP] -p [PORT]", "smtp"])

		self.actions.setValue("ftp-default", ["Check for default ftp credentials", "hydra -s [PORT] -C ./wordlists/ftp-default-userpass.txt -u -o \"[OUTPUT].txt\" -f [IP] ftp", "ftp"])
		self.actions.setValue("mssql-default", ["Check for default mssql credentials", "hydra -s [PORT] -C ./wordlists/mssql-default-userpass.txt -u -o \"[OUTPUT].txt\" -f [IP] mssql", "ms-sql-s"])
		self.actions.setValue("mysql-default", ["Check for default mysql credentials", "hydra -s [PORT] -C ./wordlists/mysql-default-userpass.txt -u -o \"[OUTPUT].txt\" -f [IP] mysql", "mysql"])
		self.actions.setValue("oracle-default", ["Check for default oracle credentials", "hydra -s [PORT] -C ./wordlists/oracle-default-userpass.txt -u -o \"[OUTPUT].txt\" -f [IP] oracle-listener", "oracle-tns"])
		self.actions.setValue("postgres-default", ["Check for default postgres credentials", "hydra -s [PORT] -C ./wordlists/postgres-default-userpass.txt -u -o \"[OUTPUT].txt\" -f [IP] postgres", "postgresql"])
		#self.actions.setValue("snmp-default", ["Check for default community strings", "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt [IP]", "snmp,snmptrap"])
		#self.actions.setValue("snmp-default", ["Check for default community strings", "python ./scripts/snmpbrute.py.old -t [IP] -p [PORT] -f ./wordlists/snmp-default.txt", "snmp,snmptrap"])
		self.actions.setValue("snmp-default", ["Check for default community strings", "python ./scripts/snmpbrute.py -t [IP] -p [PORT] -f ./wordlists/snmp-default.txt -b --no-colours", "snmp,snmptrap"])
		self.actions.setValue("snmp-brute", ["Bruteforce community strings (medusa)", "bash -c \"medusa -h [IP] -u root -P ./wordlists/snmp-default.txt -M snmp | grep SUCCESS\"", "snmp,snmptrap"])
		self.actions.setValue("oracle-version", ["Get version", "msfcli auxiliary/scanner/oracle/tnslsnr_version rhosts=[IP] E", "oracle-tns"])
		self.actions.setValue("oracle-sid", ["Oracle SID enumeration", "msfcli auxiliary/scanner/oracle/sid_enum rhosts=[IP] E", "oracle-tns"])
		###
		self.actions.endGroup()

		self.actions.beginGroup('PortTerminalActions')
		self.actions.setValue("netcat", ["Open with netcat", "nc -v [IP] [PORT]", ""])
		self.actions.setValue("telnet", ["Open with telnet", "telnet [IP] [PORT]", ""])
		self.actions.setValue("ftp", ["Open with ftp client", "ftp [IP] [PORT]", "ftp"])
		self.actions.setValue("mysql", ["Open with mysql client (as root)", "mysql -u root -h [IP] --port=[PORT] -p", "mysql"])
		self.actions.setValue("mssql", ["Open with mssql client (as sa)", "python /usr/share/doc/python-impacket/examples/mssqlclient.py -p [PORT] sa@[IP]", "mys-sql-s,codasrv-se"])
		self.actions.setValue("ssh", ["Open with ssh client (as root)", "ssh root@[IP] -p [PORT]", "ssh"])
		self.actions.setValue("psql", ["Open with postgres client (as postgres)", "psql -h [IP] -p [PORT] -U postgres", "postgres"])
		self.actions.setValue("rdesktop", ["Open with rdesktop", "rdesktop [IP]:[PORT]", "ms-wbt-server"])
		self.actions.setValue("rpcclient", ["Open with rpcclient (NULL session)", "rpcclient [IP] -p [PORT] -U%", "netbios-ssn,microsoft-ds"])
		self.actions.setValue("vncviewer", ["Open with vncviewer", "vncviewer [IP]:[PORT]", "vnc"])
		self.actions.setValue("xephyr", ["Open with Xephyr", "Xephyr -query [IP] :1", "xdmcp"])
		self.actions.setValue("rlogin", ["Open with rlogin", "rlogin -i root -p [PORT] [IP]", "login"])
		self.actions.setValue("rsh", ["Open with rsh", "rsh -l root [IP]", "shell"])

		self.actions.endGroup()

		self.actions.beginGroup('SchedulerSettings')
		self.actions.setValue("nikto",["http,https,ssl,soap,http-proxy,http-alt,https-alt","tcp"])
		self.actions.setValue("screenshooter",["http,https,ssl,http-proxy,http-alt,https-alt","tcp"])
		self.actions.setValue("smbenum",["microsoft-ds","tcp"])
#		self.actions.setValue("enum4linux","netbios-ssn,microsoft-ds")
#		self.actions.setValue("smb-null-sessions","netbios-ssn,microsoft-ds")
#		self.actions.setValue("nbtscan","netbios-ns")
		self.actions.setValue("snmpcheck",["snmp","udp"])
		self.actions.setValue("x11screen",["X11","tcp"])
		self.actions.setValue("snmp-default",["snmp","udp"])
		self.actions.setValue("smtp-enum-vrfy",["smtp","tcp"])
		self.actions.setValue("mysql-default",["mysql","tcp"])
		self.actions.setValue("mssql-default",["ms-sql-s","tcp"])
		self.actions.setValue("ftp-default",["ftp","tcp"])
		self.actions.setValue("postgres-default",["postgresql","tcp"])
		self.actions.setValue("oracle-default",["oracle-tns","tcp"])

		self.actions.endGroup()

		self.actions.sync()

	# NOTE: the weird order of elements in the functions below is due to historical reasons. Change this some day.

	def getGeneralSettings(self):
		settings = dict()
		self.actions.beginGroup('GeneralSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.update({str(k):str(self.actions.value(k).toString())})
		self.actions.endGroup()
		return settings

	def getBruteSettings(self):
		settings = dict()
		self.actions.beginGroup('BruteSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.update({str(k):str(self.actions.value(k).toString())})
		self.actions.endGroup()
		return settings

	def getStagedNmapSettings(self):
		settings = dict()
		self.actions.beginGroup('StagedNmapSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.update({str(k):str(self.actions.value(k).toString())})
		self.actions.endGroup()
		return settings

	def getToolSettings(self):
		settings = dict()
		self.actions.beginGroup('ToolSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.update({str(k):str(self.actions.value(k).toString())})
		self.actions.endGroup()
		return settings

	# this function fetches all the host actions from the settings file
	def getHostActions(self):
		hostactions = []
		sortArray = []
		self.actions.beginGroup('HostActions')
		keys = self.actions.childKeys()
		for k in keys:
			hostactions.append([self.actions.value(k).toList()[0].toString(), str(k), self.actions.value(k).toList()[1].toString()])
			sortArray.append(self.actions.value(k).toList()[0].toString())
		self.actions.endGroup()
		sortArrayWithArray(sortArray, hostactions)						# sort by label so that it appears nicely in the context menu
		return hostactions

	# this function fetches all the port actions from the settings file
	def getPortActions(self):
		portactions = []
		sortArray = []
		self.actions.beginGroup('PortActions')
		keys = self.actions.childKeys()
		for k in keys:
			portactions.append([self.actions.value(k).toList()[0].toString(), str(k), self.actions.value(k).toList()[1].toString(), self.actions.value(k).toList()[2].toString()])
			sortArray.append(self.actions.value(k).toList()[0].toString())
		self.actions.endGroup()
		sortArrayWithArray(sortArray, portactions)						# sort by label so that it appears nicely in the context menu
		return portactions

	# this function fetches all the port actions that will be run as terminal commands from the settings file
	def getPortTerminalActions(self):
		portactions = []
		sortArray = []
		self.actions.beginGroup('PortTerminalActions')
		keys = self.actions.childKeys()
		for k in keys:
			portactions.append([self.actions.value(k).toList()[0].toString(), str(k), self.actions.value(k).toList()[1].toString(), self.actions.value(k).toList()[2].toString()])
			sortArray.append(self.actions.value(k).toList()[0].toString())
		self.actions.endGroup()
		sortArrayWithArray(sortArray, portactions)						# sort by label so that it appears nicely in the context menu
		return portactions

	def getSchedulerSettings(self):
		settings = []
		self.actions.beginGroup('SchedulerSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.append([str(k),self.actions.value(k).toList()[0].toString(),self.actions.value(k).toList()[1].toString()])
		self.actions.endGroup()
		return settings

	def getSchedulerSettings_old(self):
		settings = dict()
		self.actions.beginGroup('SchedulerSettings')
		keys = self.actions.childKeys()
		for k in keys:
			settings.update({str(k):str(self.actions.value(k).toString())})
		self.actions.endGroup()
		return settings

	def backupAndSave(self, newSettings):
		# Backup and save
		print '[+] Backing up old settings and saving new settings..'
		os.rename('./sparta.conf', './'+getTimestamp()+'-sparta.conf')
		self.actions = QtCore.QSettings('./sparta.conf', QtCore.QSettings.NativeFormat)

		self.actions.beginGroup('GeneralSettings')
		self.actions.setValue('default-terminal',newSettings.general_default_terminal)
		self.actions.setValue('tool-output-black-background',newSettings.general_tool_output_black_background)
		self.actions.setValue('screenshooter-timeout',newSettings.general_screenshooter_timeout)
		self.actions.setValue('web-services',newSettings.general_web_services)
		self.actions.setValue('enable-scheduler',newSettings.general_enable_scheduler)
		self.actions.setValue('enable-scheduler-on-import',newSettings.general_enable_scheduler_on_import)
		self.actions.setValue('max-fast-processes', newSettings.general_max_fast_processes)
		self.actions.setValue('max-slow-processes', newSettings.general_max_slow_processes)
		self.actions.endGroup()

		self.actions.beginGroup('BruteSettings')
		self.actions.setValue('store-cleartext-passwords-on-exit',newSettings.brute_store_cleartext_passwords_on_exit)
		self.actions.setValue('username-wordlist-path',newSettings.brute_username_wordlist_path)
		self.actions.setValue('password-wordlist-path',newSettings.brute_password_wordlist_path)
		self.actions.setValue('default-username',newSettings.brute_default_username)
		self.actions.setValue('default-password',newSettings.brute_default_password)
		self.actions.setValue('services', newSettings.brute_services)
		self.actions.setValue('no-username-services', newSettings.brute_no_username_services)
		self.actions.setValue('no-password-services', newSettings.brute_no_password_services)
		self.actions.endGroup()

		self.actions.beginGroup('StagedNmapSettings')
		self.actions.setValue('stage1-ports',newSettings.tools_nmap_stage1_ports)
		self.actions.setValue('stage2-ports',newSettings.tools_nmap_stage2_ports)
		self.actions.setValue('stage3-ports',newSettings.tools_nmap_stage3_ports)
		self.actions.setValue('stage4-ports',newSettings.tools_nmap_stage4_ports)
		self.actions.setValue('stage5-ports',newSettings.tools_nmap_stage5_ports)
		self.actions.endGroup()

		self.actions.beginGroup('HostActions')
		for a in newSettings.hostActions:
			self.actions.setValue(a[1], [a[0], a[2]])
		self.actions.endGroup()

		self.actions.beginGroup('PortActions')
		for a in newSettings.portActions:
			self.actions.setValue(a[1], [a[0], a[2], a[3]])
		self.actions.endGroup()

		self.actions.beginGroup('PortTerminalActions')
		for a in newSettings.portTerminalActions:
			self.actions.setValue(a[1], [a[0], a[2], a[3]])
		self.actions.endGroup()

		self.actions.beginGroup('SchedulerSettings')
		for tool in newSettings.automatedAttacks:
			self.actions.setValue(tool, newSettings.automatedAttacks[tool])
		self.actions.endGroup()

		self.actions.sync()

# This class first sets all the default settings and then overwrites them with the settings found in the configuration file
class Settings():
	def __init__(self, appSettings=None):

		# general
		self.general_default_terminal = "gnome-terminal"
		self.general_tool_output_black_background = "False"
		self.general_screenshooter_timeout = "15000"
		self.general_web_services = "http,https,ssl,soap,http-proxy,http-alt,https-alt"
		self.general_enable_scheduler = "True"
		self.general_max_fast_processes = "10"
		self.general_max_slow_processes = "10"

		# brute
		self.brute_store_cleartext_passwords_on_exit = "True"
		self.brute_username_wordlist_path = "/usr/share/wordlists/"
		self.brute_password_wordlist_path = "/usr/share/wordlists/"
		self.brute_default_username = "root"
		self.brute_default_password = "password"
		self.brute_services = "asterisk,afp,cisco,cisco-enable,cvs,firebird,ftp,ftps,http-head,http-get,https-head,https-get,http-get-form,http-post-form,https-get-form,https-post-form,http-proxy,http-proxy-urlenum,icq,imap,imaps,irc,ldap2,ldap2s,ldap3,ldap3s,ldap3-crammd5,ldap3-crammd5s,ldap3-digestmd5,ldap3-digestmd5s,mssql,mysql,ncp,nntp,oracle-listener,oracle-sid,pcanywhere,pcnfs,pop3,pop3s,postgres,rdp,rexec,rlogin,rsh,s7-300,sip,smb,smtp,smtps,smtp-enum,snmp,socks5,ssh,sshkey,svn,teamspeak,telnet,telnets,vmauthd,vnc,xmpp"
		self.brute_no_username_services = "cisco,cisco-enable,oracle-listener,s7-300,snmp,vnc"
		self.brute_no_password_services = "oracle-sid,rsh,smtp-enum"

		# tools
		self.tools_nmap_stage1_ports = "T:80,443"
		self.tools_nmap_stage2_ports = "T:25,135,137,139,445,1433,3306,5432,U:137,161,162,1434"
		self.tools_nmap_stage3_ports = "T:23,21,22,110,111,2049,3389,8080,U:500,5060"
		self.tools_nmap_stage4_ports = "T:0-20,24,26-79,81-109,112-134,136,138,140-442,444,446-1432,1434-2048,2050-3305,3307-3388,3390-5431,5433-8079,8081-29999"
		self.tools_nmap_stage5_ports = "T:30000-65535"

		self.tools_path_nmap = "/usr/bin/nmap"
		self.tools_path_hydra = "/usr/bin/hydra"
		self.tools_path_cutycapt = "/usr/bin/cutycapt"
		self.tools_path_texteditor = "/usr/bin/leafpad"

		self.hostActions = []
		self.portActions = []
		self.portTerminalActions = []
		self.stagedNmapSettings = []
		self.automatedAttacks = []

		# now that all defaults are set, overwrite with whatever was in the .conf file (stored in appSettings)
		if appSettings:
			try:
				self.generalSettings = appSettings.getGeneralSettings()
				self.bruteSettings = appSettings.getBruteSettings()
				self.stagedNmapSettings = appSettings.getStagedNmapSettings()
				self.toolSettings = appSettings.getToolSettings()
				self.hostActions = appSettings.getHostActions()
				self.portActions = appSettings.getPortActions()
				self.portTerminalActions = appSettings.getPortTerminalActions()
				self.automatedAttacks = appSettings.getSchedulerSettings()

				# general
				self.general_default_terminal = self.generalSettings['default-terminal']
				self.general_tool_output_black_background = self.generalSettings['tool-output-black-background']
				self.general_screenshooter_timeout = self.generalSettings['screenshooter-timeout']
				self.general_web_services = self.generalSettings['web-services']
				self.general_enable_scheduler = self.generalSettings['enable-scheduler']
				self.general_enable_scheduler_on_import = self.generalSettings['enable-scheduler-on-import']
				self.general_max_fast_processes = self.generalSettings['max-fast-processes']
				self.general_max_slow_processes = self.generalSettings['max-slow-processes']

				# brute
				self.brute_store_cleartext_passwords_on_exit = self.bruteSettings['store-cleartext-passwords-on-exit']
				self.brute_username_wordlist_path = self.bruteSettings['username-wordlist-path']
				self.brute_password_wordlist_path = self.bruteSettings['password-wordlist-path']
				self.brute_default_username = self.bruteSettings['default-username']
				self.brute_default_password = self.bruteSettings['default-password']
				self.brute_services = self.bruteSettings['services']
				self.brute_no_username_services = self.bruteSettings['no-username-services']
				self.brute_no_password_services = self.bruteSettings['no-password-services']

				# tools
				self.tools_nmap_stage1_ports = self.stagedNmapSettings['stage1-ports']
				self.tools_nmap_stage2_ports = self.stagedNmapSettings['stage2-ports']
				self.tools_nmap_stage3_ports = self.stagedNmapSettings['stage3-ports']
				self.tools_nmap_stage4_ports = self.stagedNmapSettings['stage4-ports']
				self.tools_nmap_stage5_ports = self.stagedNmapSettings['stage5-ports']

				self.tools_path_nmap = self.toolSettings['nmap-path']
				self.tools_path_hydra = self.toolSettings['hydra-path']
				self.tools_path_cutycapt = self.toolSettings['cutycapt-path']
				self.tools_path_texteditor = self.toolSettings['texteditor-path']

			except KeyError:
				print '\t[-] Something went wrong while loading the configuration file. Falling back to default settings for some settings.'
				print '\t[-] Go to the settings menu to fix the issues!'
				# TODO: send signal to automatically open settings dialog here

	def __eq__(self, other):											# returns false if settings objects are different
		if type(other) is type(self):
			return self.__dict__ == other.__dict__
		return False

if __name__ == "__main__":
	settings = AppSettings()
	s = Settings(settings)
	s2 = Settings(settings)
	print s == s2
	s2.general_default_terminal = 'whatever'
	print s == s2

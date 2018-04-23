#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
## [Edits]: Reward1
## [Credit]: superkojiman -- OneTwoPunch
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such 
## as smb, smtp, snmp, ftp and other. 
##
## This script really likes when you put a targets.txt file containing targets (one per line) at 
## /root/scripts/recon_enum/results/exam/targets.txt 
##-------------------------------------------------------------------------------------------------------------
## [Run]:
## Execute setup.sh in the scripts folder
## /root/scripts/recon_enum/./reconscan.py
## or 
## python /root/scripts/recon_enum/reconscan.py
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I strictly wrote it for personal use
## I have no plans to maintain updates, I did not write it to be efficient and in some cases you may find the 
## functions may not produce the desired results so use at your own risk/discretion. I wrote this script to 
## target machines in a lab environment so please only use it against systems for which you have permission!!  
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
##-------------------------------------------------------------------------------------------------------------
## [TODO]
##
## Running each script individually does not ensure their output directory paths exist...QoL feature...
## Expand SNMPrecon:
##     Extend: Additional snmpwalk strings?
## Fix DIRB scan in dirbustEVERYTHING
## Expand DNSRecon
## Expand FTP/TFTP: Utilize anonymous and credentialed DotDotPwn scan
## Expand dirTrav:
##     Extend web: Data extraction from files, option for data extraction only when given a vulnerable URL
##     INFO: File retrieve only uses first vulnerable URL...try more? ability to specify?
## Expand http:
##		Whateb on every status 200 page, parse, and present feedback
## Option to run reconscan with an IP range to pass to aliverecon
## Expand ReconScan:
##      POST SCAN COMPLETION:
##           Parse outputs and run through searchsploit and getsploit
##           If windows: give additional commands to run 
##                (if Windows AND SMB: github/enternal_check) #not mandatory because of additional dependencies
##                                                            #unless they are already in Kali...
##
## Expand ReconScan:
##      Other tools to consider: WHOIS, TheHarvester, Metagoofil, DNSRecon, Sublist3r
##      Other tools to consider: WafW00f, WAFNinja, XSS Scanner, Arachni, Spaghetti
##      Other tools to consider: WPscan, WPscanner, WPSeku, Droopescan, SSLScan, SSLyze A2SV
##
## [THOUGHTS]
## Organizing everything by IP address would probably be a lot better, but it seems like a lot of work to go through everything to make that change...
## Is it faster to launch multiple nmap scans or is it faster to run one nmap scan over multiple
## open ports discovered. Probably better with one scan if bandwidth available? 
## Not so great when new ports are discovered, maybe break reconscan out into more separate files?
## Edit web wordlist so lines never start with /? (only small percentage of them do)
## Expand: option to follow redirects in gobuster or default to follow? redirect comes at the cost of time (long time)
##       : But benefit of having less 301 / false negatives
##
## [NOTES]
## vulners.nse requires -sV flag
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time 
import errno
import shutil

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on %s:%s" % (ip_address, port)
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script         
       subprocess.call(SCRIPT, shell=True)
    return
	
def ftpEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    print "INFO: Detected ftp on %s:%s" % (ip_address, port)
    #FTPRECON in subdirectory in case ssh/telnet/mysql are present, hydra will have
    #separate hydra.restore files
    SCRIPT = "ftp/./ftprecon.py %s %s" % (ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
    return

def fingerEnum(ip_address, port):
   print "INFO: Detected Finger on %s:%s" % (ip_address, port)
   FINGERSCAN = "nmap -n -sV -Pn -vv -p %s --script=finger,vulners -oX /root/scripts/recon_enum/results/exam/finger/%s_finger.xml %s" % (port, ip_address, ip_address)
   subprocess.call(FINGERSCAN, shell=True)
   return

#NSE Documentation
#http-comments-displayer: Extract and output HTML and JavaScript comments from responses
#http-config-backup: checks for backups and swap files of common CMS and web config files
#http-default-accounts: test for access with default creds used by a variety of web applications and devices
#http-git: check for .git and retrieve as much repo information as possible
#http-grep: spider and attempt to match pages/urls against a given string. Search for email/ip by default. Configure more!
#http-ls: shows content of an "index" page
#http-method-tamper: attempt verb tamper to access password protected pages
#http-methods: find what options are supported by a server by sending OPTIONS request
#http-mobileversion-checker: check to see if a mobile UA will redirect to a mobile specific website
#http-passwd: check if vuln to dir traversal 
#http-robots.txt: checks for disallowed entries in robots.txt
##http-useragent-tester: test for various tool UA headers to see if they are allowed or not (also see robots.txt)
#http-userdir-enum: attempt to enum valid usernames on servers running mod_userdir module or similar enabled
#http-vhosts: search for web virtual hostnames by sending HEAD requests

#not run
#http-apache-negotiation: check for mod_negotiation. If GET index, does site return index or index.html,etc
#http-apache-server-status: check for mod_status and get information
#http-backup-finder: attempt to identify backup copies of discovered files (.bak, ~ files, 'copy of index.html', etc)
##http-enum: Enumerates directories used by popular web applications and servers
#http-fileupload-exploiter: tries 3 methods to exploit upload forms
#http-internal-ip-disclosure: send HTTP/1.0 request without host header to see if website will disclose IP
#http-ntlm-info: sends HTTP NTLM auth request with null domain and user, obtain NetBIOS, DNS, and OS build if available
#http-rfi-spider: crawls for RFI vulns. tests every form field and every param in URL
#http-security-headers: checks headers for security related headers
#http-shellshock: check for shellshock vulnerability
#http-sitemap-generator: spider site and display dir structure with number and types of files in each folder
#http-sql-injection: spider server looking for URLs containing queries vuln to SQLi. Extracts forms and tries to identify fields that are vuln
#http-unsafe-output-escaping: fuzz parameters and checks to see if they are reflected

def httpEnum(ip_address, port):
    print "INFO: Detected http on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap web script scan for %s:%s" % (ip_address, port)
    userAgent = "'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'" #This will replace the default nmap http agent string
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-useragent-tester,http-mobileversion-checker,http-ls,http-grep,http-git,http-comments-displayer,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,vulners --script-args http.useragent=%s -oN /root/scripts/recon_enum/results/exam/http/%s_%s_http.nmap %s" % (port, userAgent, ip_address, port, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    #can opt to invoke dirbustEVERYTHING with <url> <output filename> <tool-to-use> ie dirb or gobuster (default)
    DIRBUST = "./dirbustEVERYTHING.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    print "INFO: nikto scan started on port %s" % (port)
    NIKTOSCAN = "nikto -host http://%s -port %s -nolookup -ask auto -output /root/scripts/recon_enum/results/exam/nikto/%s_%s_nikto.xml > /root/scripts/recon_enum/results/exam/nikto/%s_%s_nikto" % (ip_address, port, ip_address, port, ip_address, port)
    subprocess.call(NIKTOSCAN, shell=True)
    print "INFO: whatweb started on port %s" % (port)
    WHATWEBFINGER = "whatweb http://%s:%s --log-xml=/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb.xml > /root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb" % (ip_address, port, ip_address, port, ip_address, port)
    subprocess.call(WHATWEBFINGER, shell=True)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on %s:%s" % (ip_address, port)
    print "INFO: Performing nmap web script scan for %s:%s" % (ip_address, port)  
    userAgent = "'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'" #This will replace the default nmap http agent string
    HTTPSCANS = "nmap -n -sV -Pn -vv -p %s --script=http-useragent-tester,http-mobileversion-checker,http-ls,http-grep,http-git,http-comments-displayer,http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,vulners --script-args http.useragent=%s -oX /root/scripts/recon_enum/results/exam/http/%s_%s_https.nmap %s" % (port, userAgent, ip_address, port, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    #can opt to invoke dirbustEVERYTHING with <url> <output filename> <tool-to-use> ie dirb or gobuster (default)
    DIRBUST = "./dirbustEVERYTHING.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    print "INFO: nikto scan started on port %s" % (port)
    NIKTOSCAN = "nikto -host https://%s -port %s -nolookup -ask auto -output /root/scripts/recon_enum/results/exam/nikto/%s_%s_S_nikto.xml > /root/scripts/recon_enum/results/exam/nikto/%s_%s_S_nikto" % (ip_address, port, ip_address, port, ip_address, port)
    subprocess.call(NIKTOSCAN, shell=True)
    print "INFO: whatweb started on port %s" % (port)
    WHATWEBFINGER = "whatweb https://%s:%s --log-xml=/root/scripts/recon_enum/results/exam/whatweb/%s_%s_S_whatweb.xml > /root/scripts/recon_enum/results/exam/whatweb/%s_%s_S_whatweb" % (ip_address, port, ip_address, port, ip_address, port)
    subprocess.call(WHATWEBFINGER, shell=True)
    return

def mssqlEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
	#MYSQLRECON in subdirectory in case multiple Hydra.restore files. default, nmap performs brute.
    print "INFO: Detected MS-SQL on %s:%s" % (ip_address, port)
    SCRIPT = "mssql/./mssqlrecon.py %s %s" % (ip_address, port)
    results = subprocess.check_output(SCRIPT, shell=True)
    return

def mysqlEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
	#MYSQLRECON in subdirectory in case ftp/ssh/telnet are present, hydra will have
    #separate hydra.restore files. default, nmap performs the brute, but just in case
    print "INFO: Detected MySQL on %s:%s" % (ip_address, port)
    SCRIPT = "mysql/./mysqlrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

#nfs-ls: attempts to get useful information about files from NFS exports.
#nfs-showmount: shows NFS exports like the 'showmount -e' command
#nfs-statfs: retrieves disk space statistics
def nfsEnum(ip_address, port):
    print "INFO: Detected NFS on %s:%s" % (ip_address, port)
    NFSSCAN = "nmap -n -sV -Pn -vv -p %s --script=nfs-ls,nfs-showmount,nfs-statfs,vulners -oX /root/scripts/recon_enum/results/exam/nfs/%s_nfs.xml %s" % (port, ip_address, ip_address)
    subprocess.call(NFSSCAN, shell=True)
    return

def rdpEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
	#RDPRECON in subdir in case multiple hydra.restore files
    print "INFO: Detected RDP on %s:%s" % (ip_address, port)
    SCRIPT = "rdp/./rdprecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def sshEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    print "INFO: Detected SSH on %s:%s" % (ip_address, port)
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on %s:%s" % (ip_address, port)
    SCRIPT = "./snmprecon.py %s" % (ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on %s:%s" % (ip_address, port)
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" % (ip_address)       
       subprocess.call(SCRIPT, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)" 
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on %s:%s" % (ip_address, port)
    if port.strip() == "139":
       SCRIPT = "./smbrecon.py %s %s" % (ip_address, port)
       subprocess.call(SCRIPT, shell=True)
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s %s" % (ip_address, port)
       subprocess.call(SCRIPT, shell=True)
    if port.strip() == "137":
       SCRIPT = "./smbrecon.py %s %s" % (ip_address, port)
       subprocess.call(SCRIPT, shell=True)
    return

def telnetEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    #TELNETRECON in subdirectory in case ftp/ssh/mysql are present, hydra will have
    #separate hydra.restore files
    print "INFO: Detected Telnet on %s:%s" % (ip_address, port)
    SCRIPT = "telnet/./telnetrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def tftpEnum(ip_address, port):
   print "INFO: Detected TFTP on %s:%s" % (ip_address, port)
   TFTPSCAN = "nmap -n -sV -Pn -vv -p %s --script=tftp-enum,vulners -oX /root/scripts/recon_enum/results/exam/tftp/%s_tftp.xml %s" % (port, ip_address, ip_address)
   subprocess.call(TFTPSCAN, shell=True)
   return
    
def fullMap(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running full TCP/UDP nmap scans for %s" % (ip_address)
   print "INFO: Full UDP takes a LONG time"
   TCPSCAN = "nmap -n -vv -Pn -sS -T 4 -p- --max-retries 1 --min-rate 300 -oN '/root/scripts/recon_enum/results/exam/nmap/%s_FULL.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_FULL_nmap_scan_import.xml' %s"  % (ip_address, ip_address, ip_address)
   UDPSCAN = "nmap -n -vv -Pn -sU -T 4 -p- --max-retries 1 --min-rate 300 -oN '/root/scripts/recon_enum/results/exam/nmap/%sU_FULL.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%sU_FULL_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
   tcplines = subprocess.check_output(TCPSCAN, shell=True).split("\n")
   for line in tcplines:
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line): 
         while "  " in line:
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         print ("INFO: Full Nmap found TCP: %s on %s") % (service, port)   
   udplines = subprocess.check_output(UDPSCAN, shell=True).split("\n")
   for line in udplines:
      line = line.strip()
      if ("udp" in line) and ("open" in line) and not ("Discovered" in line): 
         while "  " in line:
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         print ("INFO: Full Nmap found UDP: %s on %s") % (service, port)
   print "INFO: TCP/UDP Nmap scans completed for %s" % (ip_address) 
   return

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP nmap scans for " + ip_address
   serv_dict = {}
   TCPSCAN = "nmap -n -vv -Pn -A -sC -sS -T 4 -p- -oN '/root/scripts/recon_enum/results/exam/nmap/%s.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_nmap_scan_import.xml' %s"  % (ip_address, ip_address, ip_address)
   UDPSCAN = "nmap -n -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '/root/scripts/recon_enum/results/exam/nmap/%sU.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
   #Scan will rarely finish, uncomment with caution
   #UDPSCANALL = "nmap -vv -Pn -sU -T 5 -p- -oN '/root/scripts/recon_enum/results/exam/nmap/%sUall.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%sUall_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
   results = subprocess.check_output(TCPSCAN, shell=True)
   udpresults = subprocess.check_output(UDPSCAN, shell=True)
   #udpallresults = subprocess.check_output(UDPSCANALL, shell=True)
   lines = results.split("\n")
   for line in lines:
      ports = []
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
	 while "  " in line: 
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
	 port = line.split(" ")[0] # grab the port/proto
         print ("INFO: all port/proto before analyzing. Some may not be analyzed in depth by default modules " + port)
         if service in serv_dict:
	    ports = serv_dict[service] # if the service is already in the dict, grab the port list
	 
         ports.append(port) 
	 serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
   
   # go through the service dictionary to call additional targeted enumeration functions 
   for serv in serv_dict: 
      ports = serv_dict[serv]	
      if (serv == "http"):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)
      elif (serv == "ssl/http") or ("https" in serv):
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpsEnum, ip_address, port)
      elif "ssh" in serv:
	 for port in ports:
	    port = port.split("/")[0]
	    multProc(sshEnum, ip_address, port)
      elif "smtp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smtpEnum, ip_address, port)
      elif "snmp" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(snmpEnum, ip_address, port)
      elif ("domain" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(dnsEnum, ip_address, port)
      elif ("ftp" in serv):
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(ftpEnum, ip_address, port)
      elif "microsoft-ds" in serv:	
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(smbEnum, ip_address, port)
      elif "ms-sql" in serv:
 	 for port in ports:
	    port = port.split("/")[0]
	    multProc(httpEnum, ip_address, port)
      
   print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
   return

#Be sure to change the interface if needed
#-mT/-mU TCP/UDP respectively, full range of ports. -L timeout 3 seconds (7 default), 300 packets per second (default)
def unicornScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP unicorn scans for " + ip_address
   TCPSCAN = "unicornscan -i eth0 -mT -p1-65535 %s -l /root/scripts/recon_enum/results/exam/unicorn/%s-tcp.txt -L 3 -r 300" % (ip_address, ip_address)
   UDPSCAN = "unicornscan -i eth0 -mU -p1-65535 %s -l /root/scripts/recon_enum/results/exam/unicorn/%s-udp.txt -L 3 -r 300" % (ip_address, ip_address)
   subprocess.check_output(TCPSCAN, shell=True)
   subprocess.check_output(UDPSCAN, shell=True)
   tcpPorts = 'cat "/root/scripts/recon_enum/results/exam/unicorn/%s-tcp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed \'s/ //g\'' % (ip_address)
   udpPorts = 'cat "/root/scripts/recon_enum/results/exam/unicorn/%s-udp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed \'s/ //g\'' % (ip_address)
   tcpPorts = subprocess.check_output(tcpPorts, shell=True).split("\n")
   print "INFO: Unicorn TCP ports %s" % tcpPorts
   udpPorts = subprocess.check_output(udpPorts, shell=True).split("\n")
   print "INFO: Unicorn UDP ports %s" % udpPorts
   #pass to nmap for versioning
   for port in tcpPorts: #the last element in the list is blank
      if port != "":
         uniNmapTCP = "nmap -n -vv -Pn -A -sC -sS -T 4 -p %s -oN '/root/scripts/recon_enum/results/exam/nmap/%s_%s.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_%s_nmap_scan_import.xml' %s"  % (port, ip_address, port, ip_address, port, ip_address)
         lines = subprocess.check_output(uniNmapTCP, shell=True).split("\n")
         print "INFO: nmap versioning for TCP %s:%s completed" % (ip_address, port)
         for line in lines:
            line = line.strip()
            if ("tcp" in line) and ("open" in line) and not ("Discovered" in line): 
               while "  " in line:
                  line = line.replace("  ", " ");
               linesplit= line.split(" ")
               service = linesplit[2] # grab the service name
               port = line.split(" ")[0] # grab the port/proto
               port = port.split("/")[0]
               if ("http" in service):
                  multProc(httpEnum, ip_address, port)
               elif ("domain" in service):
                  multProc(dnsEnum, ip_address, port)
               elif ("finger" in service):
			      multProc(fingerEnum, ip_address, port)
               elif ("ftp" in service):
                  multProc(ftpEnum, ip_address, port)
               elif ("netbios-ssn" in service):
                  multProc(smbEnum, ip_address,port)
               elif ("microsoft-ds" in service):
                  multProc(smbEnum, ip_address, port)
               elif ("ms-sql" in service or "mssql" in service):
                  multProc(mssqlEnum, ip_address, port)				  				  
               elif ("my-sql" in service or "mysql" in service):
			      multProc(mysqlEnum, ip_address, port)
               elif ("nfs" in service):
			      multProc(nfsEnum, ip_address, port)
               elif ("rdp" in service):
			      multProc(rdpEnum, ip_address, port)
               elif ("ssh/http" in service or "https" in service):
                  multProc(httpsEnum, ip_address, port)
               elif ("ssh" in service):
                  multProc(sshEnum, ip_address, port)
               elif ("smtp" in service):
                  multProc(smtpEnum, ip_address, port)
               elif ("snmp" in service):
                  multProc(snmpEnum, ip_address, port)
               elif ("telnet" in service):
			      multProc(telnetEnum, ip_address, port)
               elif ("tftp" in service):
			      multProc(tftpEnum, ip_address, port)
               
   for port in udpPorts: #the last element in the list is blank
      if port != "":
         uniNmapUDP = "nmap -n -vv -Pn -A -sC -sU -T 4 -p %s -oN '/root/scripts/recon_enum/results/exam/nmap/%s_%sU.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_%sU_nmap_scan_import.xml' %s"  % (port, ip_address, port, ip_address, port, ip_address)
         lines = subprocess.check_output(uniNmapUDP, shell=True).split("\n")
         print "INFO: nmap versioning for UDP %s:%s completed" % (ip_address, port)
         for line in lines:
            line = line.strip()
            if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
               while "  " in line:
                  line = line.replace("  ", " ");
               linesplit= line.split(" ")
               service = linesplit[2] # grab the service name
               port = line.split(" ")[0] # grab the port/proto
               port = port.split("/")[0]
               if ("domain" in service):
                  multProc(dnsEnum, ip_address, port)
   print "INFO: General TCP/UDP unicorn and nmap finished for %s. Tasks passed to designated scripts" % (ip_address)
   jobs = []
   q = multiprocessing.Process(target=fullMap, args=(scanip,)) #comma needed
   jobs.append(q)
   q.start()
   return
   
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
   scriptsToRun = "dirb","dirb/80","dirb/443","dotdotpwn","finger","ftp","http","mssql","mysql","nfs","nikto","nmap","rdp","smb","smtp","snmp","ssh","telnet","tftp","unicorn","whatweb"
   for path in scriptsToRun:
      mkdir_p("/root/scripts/recon_enum/results/exam/%s" % path)
   mkdir_p("/usr/share/dotdotpwn/Reports")

def backupExisting():
   print "INFO: Previous folders found, zipping backup"
   #tmp move targets.txt, zip files, backup, remove dirs, restore targets.txt
   moved = False
   if os.path.isfile("/root/scripts/recon_enum/results/exam/targets.txt"):
      os.rename("/root/scripts/recon_enum/results/exam/targets.txt", "/root/scripts/recon_enum/results/targets.txt")
      moved = True
   backupName = "backup_%s.tar.gz" % (time.strftime("%H:%M"))
   BACKUP = "tar czf /root/Downloads/%s /root/scripts/recon_enum/results/exam/*" % (backupName)
   backupResults = subprocess.check_output(BACKUP, shell=True)
   #ugly, but rm everything in exam and recreate empty dir to put targets.txt back
   shutil.rmtree("/root/scripts/recon_enum/results/exam")
   mkdir_p("/root/scripts/recon_enum/results/exam")
   if moved == True:
      os.rename("/root/scripts/recon_enum/results/targets.txt", "/root/scripts/recon_enum/results/exam/targets.txt")

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

# grab the discover scan results and start scanning up hosts
print "##############################################################"
print "####                      RECON SCAN                      ####"
print "####            A multi-process service scanner           ####"
print "####        finger, http, mssql, mysql, nfs, nmap,        ####"
print "####        rdp, smb, smtp, snmp, ssh, telnet, tftp       ####"
print "##############################################################"
print "############# Don't forget to start your TCPDUMP #############"
print "############ Don't forget to start your RESPONDER ############"
print "##############################################################"
print "##### This tool relies on many others. Please ensure you #####"
print "##### run setup.sh first and have all tools in your PATH #####"
print "##############################################################"


#The script creates the directories that the results will be placed in
#User needs to place the targets in the results/exam/targets.txt file
if __name__=='__main__':
   backupExisting()
   mksymlink()
   createDirectories()

   # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
   # Also check Nmap user-agent string, should be set to Firefox or other
   if os.path.isfile('/root/scripts/recon_enum/results/exam/targets.txt'):
       if os.path.getsize('/root/scripts/recon_enum/results/exam/targets.txt') > 2: #0 is empty, 2 is file with \n
           try:
               f = open('/root/scripts/recon_enum/results/exam/targets.txt', 'r')
           except:
               raise
       else:
           print "ERROR: Is targets.txt blank?! Please ensure targets.txt is populated. Run aliverecon.py or something"
           sys.exit(0)
   else:
        print "ERROR: No targets.txt detected! Please ensure targets.txt is populated. Run aliverecon.py or something"
        sys.exit(0)

   for scanip in f:
       jobs = []
#      Uncomment to maintain original nmap functionality. Comment out unicorn scan line.
#      p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       p = multiprocessing.Process(target=unicornScan, args=(scanip,)) #comma needed to only pass single arg
       jobs.append(p)
       p.start()
   f.close() 

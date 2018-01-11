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
## Something faster than DIRB (gobuster maybe?)
## Delete files/folders before scanning to ensure a fresh start? Implement a backup feature like onetwopunch
## After unicorn/nmap, run a full nmap TCP and a large nmap UDP just to make sure nothing is missed
## 
## [THOUGHTS]
## Is it faster to launch multiple nmap scans or is it faster to run one nmap scan over multiple
## open ports discovered. Probably better with one scan? 
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time 
import errno


def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def dnsEnum(ip_address, port):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() == "53":
       SCRIPT = "./dnsrecon.py %s" % (ip_address)# execute the python script         
       subprocess.call(SCRIPT, shell=True)
    return

def httpEnum(ip_address, port):
    print "INFO: Detected http on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    userAgent = "'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'" #This will replace the default nmap http agent string
    HTTPSCAN = "nmap -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt --script-args http.useragent=%s -oN /root/scripts/recon_enum/results/exam/http/%s_http.nmap %s" % (port, userAgent, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCAN, shell=True)
    DIRBUST = "./dirbustEVERYTHING.py http://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def httpsEnum(ip_address, port):
    print "INFO: Detected https on " + ip_address + ":" + port
    print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
    userAgent = "'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'" #This will replace the default nmap http agent string
    HTTPSCANS = "nmap -n -sV -Pn -vv -p %s --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt --script-args http.useragent=%s -oX /root/scripts/recon_enum/results/exam/http/%s_https.nmap %s" % (port, userAgent, ip_address, ip_address)
    results = subprocess.check_output(HTTPSCANS, shell=True)
    DIRBUST = "./dirbustEVERYTHING.py https://%s:%s %s" % (ip_address, port, ip_address) # execute the python script
    subprocess.call(DIRBUST, shell=True)
    NIKTOSCAN = "nikto -host %s -p %s > %s._nikto" % (ip_address, port, ip_address)
    return

def mssqlEnum(ip_address, port):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MSSQLSCAN = "nmap -n -sV -Pn -vv -p %s --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oX /root/scripts/recon_enum/results/exam/sql/%s_mssql.xml %s" % (port, ip_address, ip_address)
    results = subprocess.check_output(MSSQLSCAN, shell=True)

def sshEnum(ip_address, port):
    #EDIT SSHRECON WITH USERNAME/PASSWORD LISTS
    print "INFO: Detected SSH on " + ip_address + ":" + port
    SCRIPT = "./sshrecon.py %s %s" % (ip_address, port)
    subprocess.call(SCRIPT, shell=True)
    return

def snmpEnum(ip_address, port):
    print "INFO: Detected snmp on " + ip_address + ":" + port
    SCRIPT = "./snmprecon.py %s" % (ip_address)         
    subprocess.call(SCRIPT, shell=True)
    return

def smtpEnum(ip_address, port):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    if port.strip() == "25":
       SCRIPT = "./smtprecon.py %s" % (ip_address)       
       subprocess.call(SCRIPT, shell=True)
    else:
       print "WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)" 
    return

def smbEnum(ip_address, port):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() == "445":
       SCRIPT = "./smbrecon.py %s 2>/dev/null" % (ip_address)
       subprocess.call(SCRIPT, shell=True)
    return

def ftpEnum(ip_address, port):
    #EDIT FTPRECON WITH USERNAME/PASSWORD LISTS
    print "INFO: Detected ftp on " + ip_address + ":" + port
    #FTPRECON in subdirectory in case ftp and ssh are present, hydra will have
    #separate hydra.restore files
    SCRIPT = "ftp/./ftprecon.py %s %s" % (ip_address, port)       
    subprocess.call(SCRIPT, shell=True)
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
#-mT/-mU TCP/UDP respectively, %s:a is IP:a or IP:all ports
def unicornScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP unicorn scans for " + ip_address
   TCPSCAN = "unicornscan -i eth0 -mT %s:a -l /root/scripts/recon_enum/results/exam/unicorn/%s-tcp.txt" % (ip_address, ip_address)
   UDPSCAN = "unicornscan -i eth0 -mU %s:a -l /root/scripts/recon_enum/results/exam/unicorn/%s-udp.txt" % (ip_address, ip_address)
   subprocess.check_output(TCPSCAN, shell=True)
   subprocess.check_output(UDPSCAN, shell=True)
   tcpPorts = 'cat "/root/scripts/recon_enum/results/exam/unicorn/%s-tcp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed \'s/ //g\'' % (ip_address)
   udpPorts = 'cat "/root/scripts/recon_enum/results/exam/unicorn/%s-udp.txt" | grep open | cut -d"[" -f2 | cut -d"]" -f1 | sed \'s/ //g\'' % (ip_address)
   tcpPorts = subprocess.check_output(tcpPorts, shell=True).split("\n")
   udpPorts = subprocess.check_output(udpPorts, shell=True).split("\n")
   print "INFO: TCP ports %s" % tcpPorts
   print "INFO: UDP ports %s" % udpPorts
   #pass to nmap for versioning
   for port in tcpPorts: #the last element in the list is blank
      if port != "":
         print("TCP: " + port)
         uniNmapTCP = "nmap -n -vv -Pn -A -sC -sS -T 4 -p %s -oN '/root/scripts/recon_enum/results/exam/nmap/%s_%s.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_%s_nmap_scan_import.xml' %s"  % (port, ip_address, port, ip_address, port, ip_address)
         lines = subprocess.check_output(uniNmapTCP, shell=True).split("\n")
         for line in lines:
            line = line.strip()
            #I don't think this is necessary because we are only feeding nmap open ports
            #as discovered by unicornscan
            if ("tcp" in line) and ("open" in line) and not ("Discovered" in line): 
               while "  " in line:
                  line = line.replace("  ", " ");
               linesplit= line.split(" ")
               service = linesplit[2] # grab the service name
               port = line.split(" ")[0] # grab the port/proto
               port = port.split("/")[0]
               if ("http" in service):
                  multProc(httpEnum, ip_address, port)
               elif ("ssh/http" in service) or ("https" in service):
                  multProc(httpsEnum, ip_address, port)
               elif ("ssh" in service):
                  multProc(sshEnum, ip_address, port)
               elif ("smtp" in service):
                  multProc(smtpEnum, ip_address, port)
               elif ("snmp" in service):
                  multProc(snmpEnum, ip_address, port)
               elif ("domain" in service):
                  multProc(dnsEnum, ip_address, port)
               elif ("ftp" in service):
                  multProc(ftpEnum, ip_address, port)
               elif ("microsoft-ds" in service):
                  multProc(smbEnum, ip_address, port)
               elif ("ms-sql" in service):
                  multProc(httpEnum, ip_address, port)            
            
   for port in udpPorts: #the last element in the list is blank
      if port != "":
         print("UDP: " + port)
         uniNmapUDP = "nmap -n -vv -Pn -A -sC -sU -T 4 -p %s -oN '/root/scripts/recon_enum/results/exam/nmap/%s_%sU.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_%sU_nmap_scan_import.xml' %s"  % (port, ip_address, port, ip_address, port, ip_address)
         lines = subprocess.check_output(uniNmapUDP, shell=True).split("\n")
         for line in lines:
            line = line.strip()
            #I don't think this is necessary because we are only feeding nmap open ports
            #as discovered by unicornscan
            if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
               while "  " in line:
                  line = line.replace("  ", " ");
               linesplit= line.split(" ")
               service = linesplit[2] # grab the service name
               port = line.split(" ")[0] # grab the port/proto
               port = port.split("/")[0]
               if ("http" in service):
                  multProc(httpEnum, ip_address, port)
               elif ("ssh/http" in service) or ("https" in service):
                  multProc(httpsEnum, ip_address, port)
               elif ("ssh" in service):
                  multProc(sshEnum, ip_address, port)
               elif ("smtp" in service):
                  multProc(smtpEnum, ip_address, port)
               elif ("snmp" in service):
                  multProc(snmpEnum, ip_address, port)
               elif ("domain" in service):
                  multProc(dnsEnum, ip_address, port)
               elif ("ftp" in service):
                  multProc(ftpEnum, ip_address, port)
               elif ("microsoft-ds" in service):
                  multProc(smbEnum, ip_address, port)
               elif ("ms-sql" in service):
                  multProc(httpEnum, ip_address, port)

   
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
def createDirectories():
   scriptsToRun = "nmap","ftp","ssh","http","sql","smb","smtp","unicorn","dirb"
   for path in scriptsToRun:
      mkdir_p("/root/scripts/recon_enum/results/exam/%s" % path)

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
print "############################################################"
print "####                      RECON SCAN                    ####"
print "####            A multi-process service scanner         ####"
print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
print "############################################################"
print "#############Don't forget to start your TCPDUMP#############"
print "############################################################"


#The script creates the directories that the results will be placed in
#User needs to place the targets in the results/exam/targets.txt file
if __name__=='__main__':
   f = open('results/exam/targets.txt', 'r') # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
					     # Also check Nmap user-agent string, should be set to Firefox or other
   createDirectories()
   mksymlink()
   for scanip in f:
       jobs = []
#      Uncomment to maintain original nmap functionality. Comment out unicorn scan line.
#      p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       p = multiprocessing.Process(target=unicornScan, args=(scanip,)) #comma needed to only pass single arg
       jobs.append(p)
       p.start()
   f.close() 

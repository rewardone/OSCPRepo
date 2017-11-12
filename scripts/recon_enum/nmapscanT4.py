#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
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
###############################################################################################################

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time 

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running -T 4 general TCP/UDP nmap scans for " + ip_address
   serv_dict = {}
   TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- -oN '/root/scripts/recon_enum/results/exam/%s.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%s_nmap_scan_import.xml' %s"  % (ip_address, ip_address, ip_address)
   UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '/root/scripts/recon_enum/results/exam/%sU.nmap' -oX '/root/scripts/recon_enum/results/exam/nmap/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address)
   results = subprocess.check_output(TCPSCAN, shell=True)
   udpresults = subprocess.check_output(UDPSCAN, shell=True)
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
         print ("INFO: HTTP found, consider running the HTTP module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(httpEnum, ip_address, port)
      elif (serv == "ssl/http") or ("https" in serv):
         print ("INFO: HTTPS found, consider running the HTTPS module")
	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(httpsEnum, ip_address, port)
      elif "ssh" in serv:
         print ("INFO: SSH found, consider running the SSH module")
	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(sshEnum, ip_address, port)
      elif "smtp" in serv:
         print ("INFO: SMTP found, consider running the SMTP module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(smtpEnum, ip_address, port)
      elif "snmp" in serv:
         print ("INFO: SNMP found, consider running the SNMP module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(snmpEnum, ip_address, port)
      elif ("domain" in serv):
         print ("INFO: DNS found, consider running the DNS module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(dnsEnum, ip_address, port)
      elif ("ftp" in serv):
         print ("INFO: FTP found, consider running the FTP module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(ftpEnum, ip_address, port)
      elif "microsoft-ds" in serv:
         print ("INFO: SMB found, consider running the SMB module")	
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(smbEnum, ip_address, port)
      elif "ms-sql" in serv:
         print ("INFO: SQL found, consider running the SQL module")
 	 #for port in ports:
	 #   port = port.split("/")[0]
	 #   multProc(httpEnum, ip_address, port)
      
   print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
   return

if __name__=='__main__':
   f = open('results/exam/targets.txt', 'r') # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
					     # Also check Nmap user-agent string, should be set to Firefox
   for scanip in f:
       jobs = []
       p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       jobs.append(p)
       p.start()
   f.close() 

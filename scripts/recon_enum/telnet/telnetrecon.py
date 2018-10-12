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
#TELNETSCAN = "nmap -n -sV -Pn -vv -p %s --script=banner,telnet-encryption,telnet-ntlm-info,vulners -oA '/root/scripts/recon_enum/results/exam/telnet/%s_telnet.nmap' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(TELNETSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,telnet-encryption,telnet-ntlm-info,vulners','-oA','/root/scripts/recon_enum/results/exam/telnet/%s_%s_telnet' % (ip_address,port),ip_address])

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
print "INFO: Performing hydra telnet scan against %s" % (ip_address)
#HYDRA = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/telnet/%s_telnethydra.txt -u %s -s %s telnet" % (ip_address, ip_address, port)
try:
    #results = subprocess.check_output(HYDRA, shell=True)
    #resultarr = results.split("\n")
    results = subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o','/root/scripts/recon_enum/results/exam/telnet/%s_%s_telnethydra.txt' % (ip_address,port),'-u',ip_address,'-s',port,'telnet'])
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid telnet credentials found: %s" % (result)
except subprocess.CalledProcessError as hydrerr:
    if hydrerr.returncode == 255:
        print "Hydra broke early with status 255, it must have found something! Check telnethydra for output."
    elif hydrerr.returncode != 0:
        print "Hydra broke:"
        print hydrerr.returncode
        print hydrerr.output
    else:
        print "INFO: No valid telnet credentials found"

# outfile = "/root/scripts/recon_enum/results/exam/telnet/%s_telnetrecon.txt" % (ip_address)
# f = open(outfile, "w")
# f.write(results)
# f.close

#!/usr/bin/python
import socket
import sys
import subprocess

if len(sys.argv) != 2:
    print "Usage: smtprecon.py <ip address>"
    sys.exit(0)

#SMTPSCAN = "nmap -vv -sV -Pn -p 25,465,587 --script=smtp-vuln* %s" % (sys.argv[1])
#results = subprocess.check_output(SMTPSCAN, shell=True)

#f = open("results/smtpnmapresults.txt", "a")
#f.write(results)
#f.close


print "INFO: Trying SMTP Enum on " + sys.argv[1]
names = open('/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt', 'r')
for name in names:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect=s.connect((sys.argv[1],25))
    banner=s.recv(1024)
    s.send('HELO test@test.org \r\n')
    result= s.recv(1024)
    s.send('VRFY ' + name.strip() + '\r\n')
    result=s.recv(1024)
    if ("not implemented" in result) or ("disallowed" in result):
	sys.exit("INFO: VRFY Command not implemented on " + sys.argv[1]) 
    if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
	print "[*] SMTP VRFY Account found on " + sys.argv[1] + ": " + name.strip()	
    s.close()


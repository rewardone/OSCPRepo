#!/usr/bin/python
import socket
import sys
import subprocess

if len(sys.argv) != 2:
    print "Usage: smtprecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1].strip()

#NSE Documentation
#Running
#smtp-commands: attempts to use EHLO and HELP to gather Extended commands supported by a server [--script-args smtp-commands.domain=<domain>]
#smtp-enum-users: attempt to enumerate users by using VRFY, EXPN, or RCPT TO commands. Will stop if auth is enforced.
#smtp-ntlm-info: enumerate servers that allow NTLM auth. Sending NULL NTLM will cause a response of NetBIOS, DNS, and OS build version
#smtp-vuln-cve2010-4344: check for Heap overflow within versions of EXIM prior to 4.69 (CVE-2010-4344) and priv exc in EXIM prior to 4.72 (CVE-2010-4345)
 #Warning ^ potential to crash if failed (heap corruption)
#smtp-vuln-cve2011-1720: check for memory corruption in Postfix server when using Cyrus SASL library auth (CVE-2011-1720). 
 #Warning ^ potential denial of service and possibly RCE
#smtp-vuln-cve2011-1764: check for format string vuln in Exim 4.70-4.75 with DKIM support (CVE-2011-1764). RCE with EXIM priv levels

#Not running
#smtp-brute: Brute force login/plain/cram-md5/digest-md5/NTLM
#smtp-open-relay: attempt to relay mail by issuing combination of SMTP commands.
#smtp-strageport: check if SMTP is running on non-standard port. 


print "INFO: Performing nmap SMTP script scan for " + ip_address + ":25,465,587"
SMTPSCAN = "nmap -n -sV -Pn -vv -p 25,465,587 --script=smtp-commands,smtp-enum-users,smtp-ntlm-info,smtp-vuln* -oN '/root/scripts/recon_enum/results/exam/smtp/%s_smtp.nmap' %s" % (ip_address, ip_address)
results = subprocess.check_output(SMTPSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/smtp/" + ip_address + "_smtprecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

#Below code subject to removal, replaced with nmap --script=smtp-enum-users above
# print "INFO: Trying SMTP Enum on " + sys.argv[1]
# names = open('/usr/share/wfuzz/wordlist/fuzzdb/wordlists-user-passwd/names/namelist.txt', 'r')
# for name in names:
    # s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect=s.connect((ip_address,25))
    # banner=s.recv(1024)
    # s.send('HELO test@test.org \r\n')
    # result= s.recv(1024)
    # s.send('VRFY ' + name.strip() + '\r\n')
    # result=s.recv(1024)
    # if ("not implemented" in result) or ("disallowed" in result):
	    # sys.exit("INFO: VRFY Command not implemented on " + sys.argv[1]) 
    # if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
	    # print "[*] SMTP VRFY Account found on " + ip_address + ": " + name.strip()	
    # s.close()


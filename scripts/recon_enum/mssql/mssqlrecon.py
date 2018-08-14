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
#ms-sql-dac: queries for the DAC (admin) port of an instance
#ms-sql-dump-hashes: dump hashes in format for john. requires admin.
#ms-sql-empty-password: attempts to auth using empty password for the 'sa' account.
#ms-sql-info: query browser server (UDP 1434) for info. no auth required.
#ms-sql-ntlm-info: enum info from services with NTLM auth enabled

#Not Running
#ms-sql-brute: brute
#ms-sql-config: queries for databases, linked servers, settings. auth required.
#ms-sql-hasdbaccess: queries for list of databases a user has access to. auth required.
#ms-sql-query: runs a query against server. auth required.
#ms-sql-tables: queries for a list of tables per database. auth required.
#ms-sql-xp-cmdshell: runs a command. requires admin. args 'username''password''cmd'
print "INFO: Performing nmap MSSQL script scan for %s:%s" % (ip_address, port)
#MSSQLSCAN = "nmap -n -sV -Pn -vv -p %s --script=banner,ms-sql-empty-password,ms-sql-dac,ms-sql-dump-hashes,ms-sql-info,ms-sql-ntlm-info,vulners -oA '/root/scripts/recon_enum/results/exam/mssql/%s_mssql.nmap' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(MSSQLSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ms-sql-empty-password,ms-sql-dac,ms-sql-dump-hashes,ms-sql-info,ms-sql-ntlm-info,vulners','-oA',"/root/scripts/recon_enum/results/exam/mssql/%s_%s_mssql" % (ip_address,port),ip_address])

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
print "INFO: Performing hydra mssql scan against %s" % (ip_address)
#HYDRA = "hydra -L /root/lists/userlist_sqlbrute.txt -P /root/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/mssql/%s_mssqlhydra.txt -u %s -s %s mssql" % (ip_address, ip_address, port)
try:
    #results = subprocess.check_output(HYDRA, shell=True)
    #resultarr = results.split("\n")
    results = subprocess.check_output(['hydra','-L','/root/lists/userlist_sqlbrute.txt','-P','/root/lists/quick_password_spray.txt','-f','-o','/root/scripts/recon_enum/results/exam/mssql/%s_%s_mssqlhydra.txt' % (ip_address,port),'-u',ip_address,'-s',port,'mssql']).split("\n")
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid mssql credentials found: %s" % (result)
except subprocess.CalledProcessError as hydrerr:
    if hydrerr.returncode == 255:
        print "Hydra broke early with status 255, it must have found something! Check mssqlhydra for output."
    elif hydrerr.returncode != 0:
        print "Hydra broke:"
        print hydrerr.returncode
        print hydrerr.output
    else:
        print "INFO: No valid mssql credentials found"

# outfile = "/root/scripts/recon_enum/results/exam/mssql/%s_mssqlrecon.txt" % (ip_address)
# f = open(outfile, "w")
# f.write(results)
# f.close

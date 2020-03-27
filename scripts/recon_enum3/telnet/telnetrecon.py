#!/usr/bin/env python
import subprocess
import sys
import argparse
import pathlib

#NSE Documentation
#Running
#telnet-encryption: determines whether encryption is supported. Some implement incorrectly and lead to remote root vuln.
#telnet-ntlm-info: enum information from Microsoft Telnet with NTLM auth enabled.

#Not Running
#telnet-brute: brute-force password auditing
def doNmap():
    print("INFO: Performing nmap Telnet script scan for %s:%s" % (ip_address, port))
    try:
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,telnet-encryption,telnet-ntlm-info,vulners','-oA','%s/%s_%s_telnet' % (BASE,ip_address,port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unknown exception in doNmap in telnetrecon")

#Hydra meant to do weak brute/spray, not extensive
#run manually for extensive brute
def doHydra():
    print("INFO: Performing hydra telnet scan against %s" % (ip_address))
    hydra_outfile = '%s/%s_%s_telnethydra.txt' % (BASE,ip_address,port)
    try:
        subprocess.check_output(['hydra','-L','/root/lists/userlist.txt','-P','/root/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-u',ip_address,'-s',port,'telnet'],encoding='utf8')
        with open(hydra_outfile,'r') as h:
            for result in h:
                if "login:" in result:
                    print("[*] Valid telnet credentials found: %s" % (result))
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check telnethydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: No valid telnet credentials found")

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

    BASE = '/root/scripts/recon_enum/results/exam/telnet'
    mkdir_p(BASE)

    doNmap()
    if args.Hydra:
        doHydra()
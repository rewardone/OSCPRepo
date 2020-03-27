#!/usr/bin/env python
import subprocess
import sys
import os
import argparse
import pathlib

#NSE Script documentation
#RUNNING
#ftp-anon: checks if FTP server allows anonymous logins, if so, get a dir listing
#ftp-bounce: checks if FTP server allows port scanning using the FTP bounce method, see https://en.wikipedia.org/wiki/FTP_bounce_attack
#ftp-proftpd-backdoor: check for ProFTPD 1.3.3c backdoor, OSVDB-ID 69562. If vuln, telnet or ftp and send: "HELP ACIDBITCHEZ"
#ftp-syst: sends SYST and STAT commands and returns result. SYST asks for OS info. STAT asks for server status. see https://cr.yp.to/ftp/syst.html
#ftp-vsftpd-backdoor: check for vsFTPd 2.3.4 backdoor CVE-2011-2523, send a :) and potential to execute a command
#ftp-vuln-cve-2010-4221: check for stack-based buffer overflow in ProFTPD server between 1.3.2rc3 and 1.3.3b. May crash the ftp service. Default tries to run nmap. Check exploit-db.
#tftp-enum: brute's a default list of file names to determine if they are available on the server. have to manually tftp {IP} get {filename} if discovered.
#TFTP is UDP protocol make sure it's handled correctly

#NOT RUNNING
#ftp-brute: perform brute force against FTP
#ftp-libopie: check for CVE-2010-1938, WARNING will crash if vulnerable, better to manually check...
def doNmap():
    print("INFO: Performing nmap FTP script scan for %s:%s" % (ip_address, port))
    try:
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ftp-anon,ftp-bounce,ftp-syst,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum,vulners','-oA',"%s/%s_%s_ftp" % (BASE,ip_address,port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unknown error in doNmap in ftprecon")

#user: anonymous
#pass: guest
#nmap should do anon, but here just in case
def doHydra():
    print("INFO: Performing hydra ftp scan against %s" % (ip_address))
    hydra_outfile = "%s/%s_%s_ftphydra.txt" % (BASE,ip_address,port)
    try:
        subprocess.check_output(['hydra','-L','/usr/share/wordlists/lists/userlist.txt','-P','/usr/share/wordlists/lists/quick_password_spray.txt','-f','-o',hydra_outfile,'-u',ip_address,'-s',port,'ftp'],encoding='utf8')
        with open(hydra_outfile,'r') as h:
            for result in h:
                if "login:" in result:
                    print("[*] Valid ftp credentials found: " + result)
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check ftphydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: No valid ftp credentials found")
        
def doClone():
    print("INFO: Attempting unauthenticated FTP clone against %s" % (ip_address))
    try:
        os.chdir(DUMP_DIR)
        ftp_string = "ftp://" + ip_address
        subprocess.check_output(['wget','-r','-q',ftp_string],encoding='utf8')
    except subprocess.CalledProcessError as wgeterr:
        print("Error cloning FTP with wget: " + wgeterr)

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking FTP endpoints. Usage: ftprecon.py <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', default='21', help="Specific port to enumerate")
    parser.add_argument('--hydra', default=False, action='store_true', dest='hydra', help="Specify to run hydra")
    parser.add_argument('--no-clone', default=False, action='store_true', dest='no_clone', help="Specify to run hydra")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = args.port

    BASE = '/root/scripts/recon_enum/results/exam/ftp'
    DUMP_DIR = '%s/%s_%s_DUMP' % (BASE,ip_address,port)
    mkdir_p(BASE)
    mkdir_p(DUMP_DIR)

    doNmap()
    if not args.no_clone:
        doClone()
    if args.hydra:
        doHydra()
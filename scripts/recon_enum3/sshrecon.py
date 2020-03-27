#!/usr/bin/env python
import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse
import pathlib

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
def doSSHNmap():
    print("INFO: Performing nmap SSH for %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=banner,ssh-auth-methods,sshv1,ssh2-enum-algos,vulners','-oA','%s/%s_%s_ssh' % (BASE,ip_address,port),ip_address],encoding='utf8')
    print("INFO: Finished nmap SSH for %s:%s" % (ip_address, port))
    return

def doSSLRecon():
    print("INFO: Starting nmap sslrecon for %s:%s" % (ip_address, port))
    subprocess.check_output(['./sslrecon.py', ip_address, port],encoding='utf8')
    print("INFO: Finished nmap sslrecon for %s:%s" % (ip_address, port))
    return

def doOpenSSLConnect():
    ##openssl s_client -connect server:port to attempt to fingerprint exact openssl version. opther options. works on 443, etc.
    outPath = "%s/%s_%s_openssl_connect" % (BASE, ip_address,port)
    errPath = "%s/%s_%s_openssl_connect_err" % (BASE, ip_address,port)
    try:
        #results = subprocess.check_output(OPENSSLGRAB, shell=True)
        subprocess.run(['openssl','s_client','-connect','%s:%s' % (ip_address,port)],encoding='utf8',check=True,stdout=outPath,stderr=errPath).stdout
    except subprocess.CalledProcessError as e:
        print(type(e))
        print("Unexpected error in doOpenSSLConnect in sshrecon")
        pass
    print("TTP: Remember, OpenSSH 2.3<7.4 you can Username Enum with PoC (https://www.exploit-db.com/exploits/45210/)")

def doHydra():
    print("INFO: Performing hydra ssh scan against %s:%s" % (ip_address, port))
    try:
        hydra_outfile = '%s/%s_%s_sshhydra.txt' % (BASE, ip_address, port)
        subprocess.check_output(['hydra','-L',args.userlist,'-P',args.passlist,'-f','-t',args.threads,'-o',hydra_outfile,'-u',ip_address,'-s',port,'ssh'],encoding='utf8')
        with open(hydra_outfile,'r') as h:
            for line in h:
                if "login:" in h:
                    print("[*] Valid ssh credentials found for %s: " + line % (ip_address))
    except subprocess.CalledProcessError as hydrerr:
        if hydrerr.returncode == 255:
            print("Hydra broke early with status 255, it must have found something! Check sshhydra for output.")
        elif hydrerr.returncode != 0:
            print("Hydra broke:")
            print(hydrerr.returncode)
            print(hydrerr.output)
        else:
            print("INFO: [hydra] No valid ssh credentials found for %s:%s" % (ip_address, port))

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle SSH enumeration and brute if specified (brute disabled by default). Usage: sshrecon.py {--hydra} target port')
    parser.add_argument('--hydra', default=False, action='store_true', dest='hydra', help="Specify to run hydra")
    parser.add_argument('-L', '--userlist', default='/root/lists/userlist.txt', help="Specify userlist for hydra")
    #parser.add_argument('-l', '--login', help="Specify single username for hydra")
    parser.add_argument('-P', '--passlist', default='/root/lists/quick_password_spray.txt', help="Specify passlist for hydra")
    #parser.add_argument('p', '--password', help="Specify a single password for hydra")
    parser.add_argument('-t', '--threads', default='4', help="Specify threads for hydra")
    parser.add_argument('target', help="The target IP")
    parser.add_argument('port', help="The port with SSH")

    args = parser.parse_args()

    ip_address = args.target
    port = args.port

    BASE = '/root/scripts/recon_enum/results/exam/ssh'
    mkdir_p(BASE)

    doSSHNmap()
    doSSLRecon()
    doOpenSSLConnect()
    if args.hydra:
        doHydra()

#!/usr/bin/python

import sys
import os
import subprocess
import argparse
import errno
import pathlib

# TODO: this relied on nfspy to do certain checks. Look into dockerizing nfspy and re-implementing 

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

#Running
#nfs-ls: Attempts to get useful info about files from NFS Exports
#nfs-showmount: Show NFS explorts like 'showmount -e'
#nfs-statfs: Retrieves disk space from NFS like 'df'
def doNmap(ip_address, port):
    print("INFO: Starting nfs nmap on %s:%s" % (ip_address, port))
    if len(port.split(",")) > 1:
        for ports in port.split(","):
            outfileNmap = "/root/scripts/recon_enum/results/exam/nfs/%s_%s_nfsnmap" % (ip_address, ports)  
            subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',ports,'--script','nfs-ls,nfs-showmount,nfs-statfs,vulners',"-oA",outfileNmap,ip_address],encoding='utf8')
    else:
        outfileNmap = "/root/scripts/recon_enum/results/exam/nfs/%s_%s_nfsnmap" % (ip_address, port)
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','nfs-ls,nfs-showmount,nfs-statfs,vulners',"-oA",outfileNmap,ip_address],encoding='utf8')
    print("INFO: Nfs nmap completed on %s:%s" % (ip_address, port))
    return

def doSysCommands(ip_address, port):
    print("INFO: Starting nfs sysCommands on %s:%s" % (ip_address, port))
    f = open(outfile,'w')
    DEVNULL = open(os.devnull, 'w')
    try:
        results1 = subprocess.check_output(['showmount','-a',ip_address],encoding='utf8',stderr=DEVNULL)
        if results1:
            f.write("Showmount -a: " + "\n")
            f.write(results1)
            f.write("\n")
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print("Unable to showmount -a, try manually")
        else:
            print("Unexpected error in nfsrecon doSysCommands 1")
    try:
        results2 = subprocess.check_output(['showmount','-e',ip_address],encoding='utf8',stderr=DEVNULL)
        DEVNULL.close()
        if results2:
            f.write("Showmount -e: " + "\n")
            f.write(results2)
            f.write("\n")
            f.close()
        results = results2.split("\n")
        doNfspy(results)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            print("Unable to showmount -e, try manually")
        else:
            print("Unexpected error in nfsrecon doSysCommands 2")


def doNfspy(results):
    for res in results:
        if "/" in res:
            try:
                sharename = res.split(" ")[0] #grab just the mount/share
                fqsharename = "%s:%s" % (ip_address, sharename)
                if os.path.isfile('/bin/nfspy'):
                    try:
                        dir = sharename.split("/")[-1] #grab last element so we can make a name for it
                        dir = "/mnt/%s" % dir
                        if not os.path.isdir(dir):
                            mkdir_p(dir)
                        subprocess.check_output(['nfspy',dir,'-o','server=%s,getroot,hide,allow_root,rw' % (fqsharename)],encoding='utf8')
                        print("INFO: %s should be mounted at %s" % (sharename, dir))
                    except:
                        print("Error in NFSRecon, nfspy failed")
            except:
                print("Something went wrong with nfspy or creation. Try manually for: %s" % res)
    print("INFO: nfs sysCommands completed on %s:%s" % (ip_address, port))
    return


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle nfs enumeration. Usage: nfsrecon.py ip {port}')
    parser.add_argument('ip', help="IP address of target")
    parser.add_argument('--port', default='111,2049', help="Port. Default is 111,2049")

    args = parser.parse_args()
    ip_address = args.ip
    
    if args.port != '111,2049':
        port = '111,2049,%s' % args.port #need rpc for nmap scripts
    else:
        port = '111,2049'

    BASE = "/root/scripts/recon_enum/results/exam/nfs"
    mkdir_p(BASE)
    outfile = "/root/scripts/recon_enum/results/exam/nfs/%s_%s_nfsrecon.txt" % (ip_address, port)
      

    doNmap(ip_address, port)
    doSysCommands(ip_address, port)
    print("INFO: nfsRecon completed for %s:%s" % (ip_address, port))

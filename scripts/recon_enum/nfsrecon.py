#!/usr/bin/python

import sys
import os
import subprocess
import argparse
import errno

#makedir function from https://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
#Compatible with Python >2.5, but there is a more advanced function for python 3.5
def mkdir_p(path):
   try:
      os.makedirs(path)
   except OSError as exc: #Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
         pass
      else:
         raise

#Running
#nfs-ls: Attempts to get useful info about files from NFS Exports
#nfs-showmount: Show NFS explorts like 'showmount -e'
#nfs-statfs: Retrieves disk space from NFS like 'df'
def doNmap(ip_address, port):
    print "INFO: Starting nfs nmap on %s:%s" % (ip_address, port)
    if len(port.split(",")) > 1:
        for ports in port.split(","):
            outfileNmap = "/root/scripts/recon_enum/results/exam/nfs/%s_%s_nfsnmap" % (ip_address, ports)  
            subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',ports,'--script','nfs-ls,nfs-showmount,nfs-statfs,vulners',"-oA",outfileNmap,ip_address])
    else:
        outfileNmap = "/root/scripts/recon_enum/results/exam/nfs/%s_%s_nfsnmap" % (ip_address, port)
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','nfs-ls,nfs-showmount,nfs-statfs,vulners',"-oA",outfileNmap,ip_address])
    print "INFO: Nfs nmap completed on %s:%s" % (ip_address, port)
    return

def doSysCommands(ip_address, port):
    print "INFO: Starting nfs sysCommands on %s:%s" % (ip_address, port)
    f = open(outfile,'w')
    results = subprocess.check_output(['showmount','-a',ip_address])
    if results:
        f.write("Showmount -a: " + "\n")
        f.write(results)
        f.write("\n")
    results = subprocess.check_output(['showmount','-e',ip_address])
    if results:
        f.write("Showmount -e: " + "\n")
        f.write(results)
        f.write("\n")
    results = results.split("\n")
    for res in results:
        if "/" in res:
            try:
                sharename = res.split(" ")[0] #grab just the mount/share
                fqsharename = "%s:%s" % (ip_address, sharename)
                dir = sharename.split("/")[-1] #grab last element so we can make a name for it
                dir = "/mnt/%s" % dir
                if not os.path.isdir(dir):
                    mkdir_p(dir)
                subprocess.check_output(['nfspy',dir,'-o','server=%s,getroot,hide,allow_root,rw' % (fqsharename)])
                print "INFO: %s should be mounted at %s" % (sharename, dir)
            except:
                print "Something went wrong with nfspy or creation. Try manually for: %s" % res
    f.close()
    print "INFO: nfs sysCommands completed on %s:%s" % (ip_address, port)
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
    print "INFO: nfsRecon completed for %s:%s" % (ip_address, port)

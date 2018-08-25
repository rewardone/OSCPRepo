#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse

#See more: https://github.com/nmap/nmap/tree/master/scripts

#NSE Documentation
#Running
#ssl-cert-intaddr: Reports private IPv4 address found in cert
#ssl-cert: Retrieves servers SSL cert. Output depends verbosity, -v or -vv
#ssl-heartbleed: Detection for OpenSSL Heartbleed (CVE-2014-0160) based on ssltest.py
#ssl-poodle: Checks for SSLv3 CBC ciphers (POODLE CVE-2014-3566)
#sslv2-drown: Checks for SSLv2, CVE-2015-3197, CVE-2016-0703, CVE-2016-0800 (DROWN)
#tls-nextprotoneg: Enumerates a TLS servers supported protocols
#tls-alpn: Enumerates a TLS servers supported application-layer protocols using ALPN

#Not Running
#ssl-ccs-injection: Requires tls.lua. Check if vuln to CCS vulnerability CVE-2014-0224, MitM
#ssl-date: Retrieves target hosts time and date from TLS ServerHello Response
#ssl-dh-params: Weak Diffie-Hellman param detection.
#ssl-enum-ciphers: Repeatedly initiates SSLv3/TLS connection, trying new ciphers
#ssl-known-key: Checks if SSL cert has fingerprint in db of problematic keys
#sslv2: Checks for SSLv2 and which ciphers
#sstp-discover: Check if Secure Socket Tunneling Protocol is supported

def doNmap(ip_address, port):
    print "INFO: Starting nmap sslrecon for %s:%s" % (ip_address, port)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,ssl-cert-intaddr,ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,tls-nextprotoneg,tls-alpn','-oA','%s/%s_%s_ssl' % (BASE, ip_address, port),ip_address])
    print "INFO: Finished nmap sslecon for %s:%s" % (ip_address, port)
    return


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


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle ssl enumeration, cert grab, cipher enum, etc. Usage: sslrecon.py {} target port')
    parser.add_argument('target', help="Target IP")
    parser.add_argument('port', help="Port to run scripts against")

    args = parser.parse_args()
    ip_address = args.target
    port = args.port
    #print args

    BASE = "/root/scripts/recon_enum/results/exam/ssl"

    #make sure path is created
    mkdir_p(BASE)

    doNmap(ip_address, port)

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

# --xml_out=XML_FILE        writes results to XML document
# --targets_in=TARGETS_IN   reals a list of targets. host:port per line
# --https_tunnel            tunnel through proxy. http://USER:PW@HOST:PORT
# --starttls                performs StartTLS. should be smtp, xmpp, xmpp_server, pop3, ftp, imap, ldap, rdp, postgres, auto
# --quiet                   hide standard outputs
# --regular                 shortcut for --slv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --regen --resum --certinfo=basic --http_get --hide_rejected_ciphers --compression -heartbleed
# --certinfo                should be basic or full
def doSslyze(ip_address, port):
    print "INFO: Starting sslyze for %s:%s" % (ip_address, port)
    SSLYZE = "sslyze --regular --certinfo=full %s:%s > %s/%s_%s_sslyze" % (ip_address, port, BASE, ip_address, port)
    subprocess.check_output(SSLYZE, shell=True)
    print "INFO: Finished sslyze for %s:%s" % (ip_address, port)
    return

# --targets=<file>
#--show-certificate
def doSslscan(ip_address, port):
    print "INFO: Starting sslcan for %s:%s" % (ip_address, port)
    SSLSCAN = "sslscan --show-certificate --no-colour %s:%s > %s/%s_%s_sslscan" % (ip_address, port, BASE, ip_address, port)
    subprocess.check_output(SSLSCAN, shell=True)
    print "INFO: Finished sslscan for %s:%s" % (ip_address, port)
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

    parser = argparse.ArgumentParser(description='Rough script to handle ssl enumeration, cert grab, cipher enum, etc. Usage: sslrecon.py {--nosslyze} target port')
    parser.add_argument('target', help="Target IP")
    parser.add_argument('port', help="Port to run scripts against")
    parser.add_argument('--nosslyze', default=False, help="Pass --nosslyze True to NOT run sslyze. It will run by default")
    parser.add_argument('--nosslscan', default=False, help="Pass --nosslscan True to NOT run sslscan. It will run by default")

    args = parser.parse_args()
    ip_address = args.target
    port = args.port
    #print args

    BASE = "/root/scripts/recon_enum/results/exam/ssl"

    #make sure path is created
    mkdir_p(BASE)

    doNmap(ip_address, port)
    if not args.nosslyze:
        doSslyze(ip_address, port)
    if not args.nosslscan:
        doSslscan(ip_address, port)

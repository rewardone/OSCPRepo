#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse
import pathlib

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

def doNmap():
    print("INFO: Starting nmap sslrecon for %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,ssl-cert-intaddr,ssl-cert,ssl-heartbleed,ssl-poodle,sslv2-drown,tls-nextprotoneg,tls-alpn','-oA','%s/%s_%s_ssl' % (BASE, ip_address, port),ip_address],encoding='utf8')
    print("INFO: Finished nmap sslecon for %s:%s" % (ip_address, port))
    return

# --xml_out=XML_FILE        writes results to XML document
# --targets_in=TARGETS_IN   reals a list of targets. host:port per line
# --https_tunnel            tunnel through proxy. http://USER:PW@HOST:PORT
# --starttls                performs StartTLS. should be smtp, xmpp, xmpp_server, pop3, ftp, imap, ldap, rdp, postgres, auto
# --quiet                   hide standard outputs
# --regular                 shortcut for --slv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --regen --resum --certinfo=basic --http_get --hide_rejected_ciphers --compression -heartbleed
# --certinfo                no longer takes a value
def doSslyze():
    print("INFO: Starting sslyze for %s:%s" % (ip_address, port))
    sslyze_outfile = "%s/%s_%s_sslyze" % (BASE,ip_address,port)
    try:
        subprocess.run(['sslyze','--regular','--certinfo','%s:%s' % (ip_address,port)],encoding='utf8',stdout=sslyze_outfile)
    except Exception as e:
        print(type(e))
        print("Unexpected error in doSslyze in SSLrecon")
    print("INFO: Finished sslyze for %s:%s" % (ip_address, port))
    return

# --targets=<file>
#--show-certificate
def doSslscan():
    print("INFO: Starting sslcan for %s:%s" % (ip_address, port))
    sslscan_outfile = "%s/%s_%s_sslscan" % (BASE,ip_address,port)
    try:
        subprocess.run(['sslscan','--show-certificate','--no-color','%s:%s' % (ip_address,port)],encoding='utf8',stdout=sslscan_outfile)
    except Exception as e:
        print(type(e))
        print("Unexpected error in doSslscan in SSLRecon")
    print("INFO: Finished sslscan for %s:%s" % (ip_address, port))
    return

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle ssl enumeration, cert grab, cipher enum, etc. Usage: sslrecon.py {--nosslyze} ip_address port')
    parser.add_argument('ip_address', help="Target IP")
    parser.add_argument('port', help="Port to run scripts against")
    parser.add_argument('--nosslyze', default=False, help="Pass --nosslyze True to NOT run sslyze. It will run by default")
    parser.add_argument('--nosslscan', default=False, help="Pass --nosslscan True to NOT run sslscan. It will run by default")

    args = parser.parse_args()
    ip_address = args.ip_address
    port = args.port

    BASE = "/root/scripts/recon_enum/results/exam/ssl"

    #make sure path is created
    mkdir_p(BASE)

    doNmap()
    if not args.nosslyze:
        doSslyze()
    if not args.nosslscan:
        doSslscan()

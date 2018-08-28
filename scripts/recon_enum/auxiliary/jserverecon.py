#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import argparse

#See more: https://github.com/nmap/nmap/tree/master/scripts

#NSE Documentation
#Running
#ajp-auth: Retrieve auth scheme and realm of AJP service                --script-args ajp-auth.path=/login
#ajp-headers: HEAD or GET against root and returns response headers
#ajp-methods: Discovers which options are supported by AJP
#ajp-request: Requests a URI and displays results

#Not Running
#ajp-brute: Brute auth against AJP

def doNmap(ip_address, port, userAgent):
    print "INFO: Starting nmap jserverecon for %s:%s" % (ip_address, port)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,ajp-auth,ajp-headers,ajp-methods,ajp-request,vulners','--script-args', "http.useragent=%s" % userAgent,'-oA','/root/scripts/recon_enum/results/exam/http/%s_%s_jserve' % (ip_address, port),ip_address])
    print "INFO: Finished nmap jserverecon for %s:%s" % (ip_address, port)
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

    parser = argparse.ArgumentParser(description='Rough script to handle Apache Jserve enumeration. Usage: jserverecon.py {} ip port')
    parser.add_argument('-a', '--user-agent', dest="userAgent", default="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", help="User-agent")
    parser.add_argument('ip', help="Target IP address")
    parser.add_argument('port', default="8009", help="Port of target (default 8009)")

    args = parser.parse_args()
    #print args

    ip_address = args.ip
    port = args.port

    BASE = "/root/scripts/recon_enum/results/exam/http"
    #make sure path is created
    mkdir_p(BASE)

    doNmap(ip_address, port, args.userAgent)

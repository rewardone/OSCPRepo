#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import argparse
from urllib.parse import urlparse
import pathlib

#See more: https://github.com/nmap/nmap/tree/master/scripts

#NSE Documentation
#Running
#ajp-auth: Retrieve auth scheme and realm of AJP service                --script-args ajp-auth.path=/login
#ajp-headers: HEAD or GET against root and returns response headers
#ajp-methods: Discovers which options are supported by AJP
#ajp-request: Requests a URI and displays results

#Not Running
#ajp-brute: Brute auth against AJP

def doNmap():
    print("INFO: Starting nmap jserverecon for %s:%s" % (ip_address, port))
    try:
       subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,ajp-auth,ajp-headers,ajp-methods,ajp-request,vulners','--script-args', "http.useragent=%s" % userAgent,'-oA','%s/%s_%s_jserve' % (BASE,ip_address, port),ip_address],encoding='utf8')
    except Exception as e:
        print(type(e))
        print("Unexpected error in doNmap in jserverecon")
    print("INFO: Finished nmap jserverecon for %s:%s" % (ip_address, port))
    return

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':

   parser = argparse.ArgumentParser(description='Rough script to handle Apache Jserve enumeration. Usage: jserverecon.py {} ip port')
   parser.add_argument('-a', '--user-agent', dest="userAgent", default="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", help="User-agent")
   parser.add_argument('ip', help="Target IP address")
   parser.add_argument('port', default="8009", help="Port of target (default 8009)")

   args = parser.parse_args()

   userAgent = args.userAgent

   parsed_url = urlparse(args.url)

   # get port or set default
   if not parsed_url.port:
      port = '8009' #default jserve port
   else:
      port = parsed_url.port

   # get url scheme, url_parse puts port in scheme
   if ":" in parsed_url.scheme:
      ip_address = parsed_url.scheme.split(':')[0]
   else:
      ip_address = parsed_url.scheme

   BASE = "/root/scripts/recon_enum/results/exam/http"
   mkdir_p(BASE)

   doNmap()

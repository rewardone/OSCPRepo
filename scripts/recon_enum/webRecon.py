#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse

def help():
    print "Usage: webRecon.py <http(s)://target url:port> <scan name> <tool-to-use (optional)>"
    print "tool-to-use: available options are dirb and gobuster. gobuster is the default"
    print "Warning: this version still uses old logic for dirb. gobuster uses new word list"
    print "Warning: gobuster is not set to follow redirects!"
    sys.exit(0)

if len(sys.argv) < 3:
    help()

#See more: https://github.com/nmap/nmap/tree/master/scripts
    
#NSE Documentation
#http-apache-negotiation: check for mod_negotiation. If GET index, does site return index or index.html,etc
#http-apache-server-status: attempt to retrieve server-status if mod_status is enabled  /server-status
#http-backup-finder: attempt to identify backup copies of discovered files (.bak, ~ files, 'copy of index.html', etc)
#http-comments-displayer: Extract and output HTML and JavaScript comments from responses
#http-config-backup: checks for backups and swap files of common CMS and web config files
#http-cors: tests for CORS by sending Access-Control-Request-Method headers
#http-cross-domain-policy: checks for /crossdomain.xml and /clientaccesspolicy.xml for information
#http-default-accounts: test for access with default creds used by a variety of web applications and devices
#http-git: check for .git and retrieve as much repo information as possible
#http-grep: spider and attempt to match pages/urls against a given string. Search for email/ip by default. Configure more!
#http-ls: shows content of an "index" page
#http-method-tamper: attempt verb tamper to access password protected pages
#http-methods: find what options are supported by a server by sending OPTIONS request
#http-mobileversion-checker: check to see if a mobile UA will redirect to a mobile specific website
#http-passwd: check if vuln to dir traversal
#http-robots.txt: checks for disallowed entries in robots.txt
#http-useragent-tester: test for various tool UA headers to see if they are allowed or not (also see robots.txt)
#http-userdir-enum: attempt to enum valid usernames on servers running mod_userdir module or similar enabled
#http-vhosts: search for web virtual hostnames by sending HEAD requests
#http-waf-detect: attempt to detect IPS/IDS/WAF. args: aggro,uri,detectBodyChanges
#http-waf-fingerprint: attempt to fingerprint WAF if exists. args: intensive=1
#http-webdav-scan: detect WebDAV installations using OPTIONS and PROPFIND methods

#not run
#http-apache-server-status: check for mod_status and get information
#http-devframework: attempt to spider and identify devframeworks
#http-enum: Enumerates directories used by popular web applications and servers
#http-fileupload-exploiter: tries 3 methods to exploit upload forms
#http-internal-ip-disclosure: send HTTP/1.0 request without host header to see if website will disclose IP
#http-ntlm-info: sends HTTP NTLM auth request with null domain and user, obtain NetBIOS, DNS, and OS build if available
#http-rfi-spider: crawls for RFI vulns. tests every form field and every param in URL
#http-security-headers: checks headers for security related headers
#http-shellshock: check for shellshock vulnerability
#http-sitemap-generator: spider site and display dir structure with number and types of files in each folder
#http-sql-injection: spider server looking for URLs containing queries vuln to SQLi. Extracts forms and tries to identify fields that are vuln
#http-unsafe-output-escaping: fuzz parameters and checks to see if they are reflected
def doNmap(ip_address, port, userAgent):
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','http-apache-negotiation,http-apache-server-status,http-backup-finder,http-comments-displayer,http-config-backup,http-cors,http-cross-domain-policy,http-default-accounts,http-git,http-grep,http-ls,http-methods,http-method-tamper,http-mobileversion-checker,http-passwd,http-robots.txt,http-useragent-tester,http-userdir-enum,http-vhosts,http-waf-detect,http-waf-fingerprint,http-webdav-scan','--script-args', "http.useragent=%s,http-waf-detect.aggro,http-waf-detect.detectBodyChanges,http-waf-fingerprint.intensive=1" % userAgent,'-oA','/root/scripts/recon_enum/results/exam/http/%s_%s_http' % (port, ip_address),ip_address])
    return

def doNikto(ip_address, port):
    subprocess.check_output(['nikto','-host',ip_address,'-port',port,'-nolookup','-ask','auto','-output',"/root/scripts/recon_enum/results/exam/nikto/%s_%s_nikto.xml" % (ip_address,port)])
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

    parser = argparse.ArgumentParser(description='Rough script to handle Web enumeration, fingerprinting, and other less intensive scans. Usage: webRecon.py {} <http(s)://target url:port>')
    parser = add_argument('-n', '--nmap', default='true', help="Run all (safe) nmap scripts regarding HTTP scanning")
    parser = add_argument('-k', '--nikto', default='true', help="Run nikto against site")
    parser = add_argument('-a', '--user-agent', dest="userAgent", default="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", help="User-agent")
    parser = add_argument('url', help="Run all (safe) nmap scripts regarding HTTP scanning")

    #whatweb is run after gobuster (to whatweb every page)
    #cewl is run after gobuster (to cewl more pages)
    #nmapHttpVulns is run after gobuster (to check more pages and possibly inection points)
    
    #nmap can be run here
    #nikto can be run here
    #other scripts likely to be run here

    args = parser.parse_args()
    #print args
    
    #Fix URL if "http(s)" is not pased in
    if len(args.url.split("//") == 1:
        if len(args.url.split(":") == 1:
            print "Need to specify URL:PORT
            sys.exit(1)
        elif args.url.split(":")[1] == 443:
            args.url = "https://" + args.url
        else:
            args.url = "http://" + args.url
    
    #Assign IP and PORT variables. Assigning them here
    #prevents certain edge cases from being missed above
    if ("http" in args.url):
        ip_address = args.url.strip("http://")
    elif ("https" in args.url):
        ip_address = args.url.strip("https://")
    port = args.url.split(":")[2]
    
    #make sure path is created
    path = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
    mkdir_p(path)
    
    print "INFO: Starting nmap webRecon for %s:%s) % (ip_address, port)
    doNmap(ip_address, port, args.userAgent)
    print "INFO: Finished nmap webRecon for %s:%s) % (ip_address, port)
    print "INFO: Starting nikto webRecon for %s:%s) % (ip_address, port)
    doNikto(ip_address, port)
    print "INFO: Finished nikto webRecon for %s:%s) % (ip_address, port)

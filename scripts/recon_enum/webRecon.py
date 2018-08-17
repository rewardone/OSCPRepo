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
#http-apache-negotiation: check for mod_negotiation. If GET index, does site return index or index.html,etc
#http-apache-server-status: attempt to retrieve server-status if mod_status is enabled  /server-status
#http-aspnet-debug: Determines if an ASP.NET has debugging enabled using HTTP DEBUG
#http-auth-finder: Spiders a site to find web pages requiring form-based or HTTP-based authentication
#http-auth: Retrieves the authentication scheme and realm of a web services that requires auth
#http-backup-finder: attempt to identify backup copies of discovered files (.bak, ~ files, 'copy of index.html', etc)
#http-bigip-cookie: Decodes unencrypted F5 BIG-IP cookies in HTTP responses
#http-cakephp-version: Version CakePHP by detecting certain files
#http-cisco-anyconnect: Connect as Cisco AnyConnect client to Cisco SSL VPN and retrieves  version and tunnel information
#http-comments-displayer: Extract and output HTML and JavaScript comments from responses
#http-config-backup: checks for backups and swap files of common CMS and web config files
#http-cookie-flags: Examines cookies and reports on flags and paths
#http-cors: tests for CORS by sending Access-Control-Request-Method headers
#http-cross-domain-policy: checks for /crossdomain.xml and /clientaccesspolicy.xml for information
#http-default-accounts: test for access with default creds used by a variety of web applications and devices
#http-drupal-enum: Enum installed Drupal modules/themes by using a list of known modules and themes
#http-favicon: Gets the favicon, hashes it, and checks against known applications for fingerprinting
#http-generator: Displays contents of the “generator” meta tag of a web page if it exists
#http-git: check for .git and retrieve as much repo information as possible
#http-grep: spider and attempt to match pages/urls against a given string. Search for email/ip by default. Configure more!
#http-headers: Performs a HEAD request and displays headers
#http-jsonp-detection: Attempt to discover JSONP endpoints (possible use for bypass Same Origin Policy)
#http-ls: shows content of an "index" page
#http-mcmp: Checks if server allows mod_cluster management protocol (MCMP) methods
#http-method-tamper: Attempt to verb tamper to access protected resources
#http-methods: find what options are supported by a server by sending OPTIONS request
#http-mobileversion-checker: check to see if a mobile UA will redirect to a mobile specific website
#http-ntlm-info: sends HTTP NTLM auth request with null domain and user, obtain NetBIOS, DNS, and OS build if available
#http-passwd: check if vuln to dir traversal
#http-php-version: Attempts to retrieve PHP version through use of Magic Queries
#http-robots.txt: checks for disallowed entries in robots.txt
#http-title: Shows the title of the default page of a web server
#http-traceroute: Detect the presence of reverse proxies
#http-unsafe-output-escaping: fuzz parameters and checks to see if they are reflected
#http-useragent-tester: test for various tool UA headers to see if they are allowed or not (also see robots.txt)
#http-userdir-enum: attempt to enum valid usernames on servers running mod_userdir module or similar enabled
#http-vhosts: search for web virtual hostnames by sending HEAD requests
#http-vlcstreamer-ls: Connects to a VLC Streamer helper service and lists dir contents
#http-waf-detect: attempt to detect IPS/IDS/WAF. args: aggro,uri,detectBodyChanges
#http-waf-fingerprint: attempt to fingerprint WAF if exists. args: intensive=1
#http-webdav-scan: detect WebDAV installations using OPTIONS and PROPFIND methods

#Not Running
#http-affiliate-id: Grab affiliate network IDs (AdSense, analytics, amazon, etc)
#http-avaya-ipoffice-users: Enumerate users in Avaya IP office systems
#http-brute: Brute against http basic, digest, and ntlm auth
#http-chrono: Measure time it takes for website to deliver a page and returns statistics
#http-date: Gets date from services and prints diff
#http-devframework: attempt to spider and identify devframeworks (better tools to more accurately detect)
#http-enum: Enumerates directories used by popular web applications and servers (args to make it better, complex, but could be worth it)
#http-errors: Crawls and reports on error pages
#http-exif-spider: Spider images looking for ‘interesting’ exif data
#http-feed: Crawls for RSS or atom feeds
#http-fetch: used to fetch files from servers
#http-fileupload-exploiter: tries 3 methods to exploit upload forms
#http-form-brute: Brute force pass against http form-based auth
#http-form-fuzzer: Fuzz fields in forms it detects (requires specific args/setup)
#http-gitweb-projects-enum: Retrieves a list of Git projects, owners, and descriptions from a gitweb
#http-google-malware: Checks if hosts are on Google’s blacklist
#http-icloud-findmyiphone: Retrieves locations of all “find my iphone” enabled iOS devices by querying MobleMe (auth required)
#http-icloud-sendmsg: Sennds message to iOS through MobleMe
#http-internal-ip-disclosure: send HTTP/1.0 request without host header to see if website will disclose IP
#http-joomla-brute: Joomla auth brute 
#http-malware-host: Looks for signature of known server compromises (attempts to detect servers that always return 302)
#http-open-proxy: Attempt to connect to google through the proxy
#http-proxy-brute: Brute against HTTP proxy servers
#http-put: Upload local file using HTTP PUT
#http-qnap-nas-info: Retrieve model, firmware, and enabled services from a QNAP NAS
#http-referer-checker: Spiders and informs about cross-domain include of scripts
#http-rfi-spider: crawls for RFI vulns. tests every form field and every param in URL (specific tools to test this and configure this better)
#http-robtex-reverse-ip: Obtains up to 100 forward DNS for target IP by querying Robtex
#http-robtex-shared-ns: Obtains up to 100 domain names which use same name server as target by querying Robtex
#http-security-headers: checks headers for security related headers (headers could be different by page, really best to analyze these per request through a proxy or other)
#http-server-header: HTTP server header for missing version info (infeasible with version probes)
#http-sitemap-generator: spider site and display dir structure with number and types of files in each folder (dir brute force better)
#http-svn-enum: Enum users of Subversion repo by examining logs of recent commits
#http-svn-info: Requests information from subversion repo
#http-trace: Identifies if TRACE is enabled
#http-trane-info: Obtain info from HVAC equipment controllers
#http-virustotal: Checks whether file has been determined as malware by Virustotal
#http-wordpress-brute: Brute wordpress auth
#http-wordpress-enum: Brute wordpress themes/plugins
#http-wordpress-users: Enum wordpress users
#http-xssed: Searches xssed.com database and outputs results
#https-redirect: Checks for HTTP redirects to HTTPS on same port

def doNmap(ip_address, port, userAgent):
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','banner,http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-auth-finder,http-auth,http-backup-finder,http-bigip-cookie,http-cakephp-version,http-cisco-anyconnect,http-comments-displayer,http-config-backup,http-cookie-flags,http-cors,http-cross-domain-policy,http-default-accounts,http-drupal-enum,http-favicon,http-generator,http-git,http-grep,http-headers,http-jsonp-detection,http-ls,http-mcmp,http-method-tamper,http-methods,http-mobileversion-checker,http-ntlm-info,http-passwd,http-php-version,http-robots.txt,http-title,http-traceroute,http-unsafe-output-escaping,http-useragent-tester,http-userdir-enum,http-vhosts,http-vlcstreamer-ls,http-waf-detect,http-waf-fingerprint,http-webdav-scan','--script-args', "http.useragent=%s,http-waf-detect.aggro,http-waf-detect.detectBodyChanges,http-waf-fingerprint.intensive=1" % userAgent,'-oA','/root/scripts/recon_enum/results/exam/http/%s_%s_http' % (port, ip_address),ip_address])
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
    parser.add_argument('-n', '--nmap', default='true', help="Run all (safe) nmap scripts regarding HTTP scanning")
    parser.add_argument('-k', '--nikto', default='true', help="Run nikto against site")
    parser.add_argument('-a', '--user-agent', dest="userAgent", default="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", help="User-agent")
    parser.add_argument('url', help="Run all (safe) nmap scripts regarding HTTP scanning")

    #whatweb is run after gobuster (to whatweb every page)
    #cewl is run after gobuster (to cewl more pages)
    #nmapHttpVulns is run after gobuster (to check more pages and possibly inection points)

    #nmap can be run here
    #nikto can be run here
    #other scripts likely to be run here

    args = parser.parse_args()
    #print args

    #Fix URL if "http(s)" is not pased in
    if len(args.url.split("//")) == 1: #1 means there is no http:// before URL
        if len(args.url.split(":")) == 1: #1 means there is no port passed in
            print "Need to specify URL:PORT"
            sys.exit(1)
        elif len(args.url.split(":")) == 2:
            #this happens after split("//") so this should mean URL is [0] and [PORT] is [1]
            if args.url.split(":")[1] == 443: #hard code 443
                tmp = args.url.split(":")
                ip_address = tmp[0]
                port = 443
                args.url = "https://" + args.url
            else:
                tmp = args.url.split(":")
                ip_address = tmp[0]
                port = tmp[1]
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

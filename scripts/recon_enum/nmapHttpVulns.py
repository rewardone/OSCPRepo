#!/usr/bin/env python

import sys
import os
import subprocess
import errno
import time
import multiprocessing
from multiprocessing import Process
import argparse

def mkdir_p(path):
   try:
      os.makedirs(path)
   except OSError as exc: #Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
         pass
      else:
         raise

#NSE Documentation
#Running
#http-adobe-coldfusion-apsa1301: Exploit an auth bypass in Coldfusion
#http-awstatstotals-exec: Exploits RCE in Awstats Totals 1-1.14
#http-axis2-dir-traversal: Exploits a dirTrav vuln in Apache Axis2 version 1.4.1
#http-barracuda-dir-traversal: Attempts to retrieve conf from Barracuda Networks Spam & Virus Firewall using DirTrav
#http-coldfusion-subzero: Retrieve version, abs path of admin panel from vulnerable ColdFusion 9 and 10
#http-csrf: Detects CSRF (possibly unreliable)
#http-dombased-xss: Looks where attacker-controlled info in DOM may be used to affect JavaScript
#http-drupal-enum-users: Enumerates Drual users by exploiting information disclosure vuln
#http-frontpage-login: Checks whether target machiens are vuln to anonymous Frontpage login
#http-iis-webdav-vuln: IIS vuln 5.1/6.0 access to secured WebDAV folders
#http-litespeed-sourcecode-download: Exploits null-byte poisoning in Litespeed 4-4.0.15
#http-majordomo2-dir-traversal: Exploits dirTrav in Majordomo2
#http-open-redirect: Spiders and attempts to identify open redirects
#http-phpmyadmin-dir-traversal: Exploits dirTrav in phpMyAdmin 2.6.4
#http-shellshock: Attempt to exploit CVE-2014-6271 and CVE-2014-7169 Shellshock vulnerability in web applications http-shellshock.uri=/
#http-sql-injection: Very basic attempt to show SQL errors in forms.
#http-vmware-path-vuln: Checks for dirTrav in VMWare ESX, ESXi, and Server (2009)
#http-vuln-cve2006-3392: Webmin before 1.290 and Usermin before 1.220 file disclosure using %01
#http-vuln-cve2009-3960: Adobe XML External Entity Injection. Read local files in BlazeDS <3.2, LiveCycle 8.0.1 8.2.1 and 9, LiveCycleData Services 2.5.1 2.6.1 and 3, Flex Data Service 2.0.1 and ColdFusion 7.0.2 8.0 8.0.1 and 9.0
#http-vuln-cve2010-0738: JBoss target is vulnerable to JMX console auth bypass via HEAD request
#http-vuln-cve2010-2861: Dir trav against ColdFusion to grab password hash for admin, use hidden salt to crate SHA1 hash and authenticate as admin (ColdFusion pass the hash)
#http-vuln-cve2011-3368: Reverse Proxy Bypass vuln in Apache. Loopback test, internal hosts test,  external website test
#http-vuln-cve2012-1823: PHP-CGI installations that are vuln to this cve. Retrieve source code and execute code. append multiple ?
#http-vuln-cve2013-0156: Ruby on Rails object injection, remote command exec, and DoS. All Ruby < 2.3.15, 3.0.x - 3.0.19, 3.1.x - 3.1.10, and 3.2.x - 3.2.11 are vuln. If 500 response, likely vulnerable
#http-vuln-cve2013-7091: Zimbra 7.2.6 local file inclusion
#http-vuln-cve2014-2126: Cisco ASA ASDM Priv Esc
#http-vuln-cve2014-2127: Cisco ASA ASDM Priv Esc
#http-vuln-cve2014-2128: Cisco ASA SSL VPN Auth bypass
#http-vuln-cve2014-3704: Drupalgeddon < 7.32, injects new admin and attempt to log in
#http-vuln-cve2014-8877: Wordpress CM Download Manager plugin <= 2.0.0 remote code injection
#http-vuln-cve2015-1427: Elasticsearch 1.3.0-1.3.7 1.4.0-1.4.2 RCE in groovy
#http-vuln-cve2015-1635: RCE in Windows Systems. HTTP request with no impact on the system to detect. Win 7,8,8.1 and server 2012,2012R2
#http-vuln-cve2017-1001000: Wordpress 4.7.0 4.7.1 priv esc
#http-vuln-cve2017-5638: Apache Struts RCE
#http-vuln-cve2017-5689: Intel AMT priv esc
#http-vuln-cve2017-8917: Joomla 3.7 - 3.7.1 SQLi
#http-vuln-misfortune-cookie: RomPager 4.07 Misfortune Cookie RCE
#http-vuln-wnr1000-creds: WNR admin creds 1.0.260_60-0.86 and 1.0.2.54_60.0.82


#Not running
#http-dlink-backdoor: Detects firmware backdoor on some D-Link routers via User-Agent
#http-domino-enum-passwords: Enum hashed Domino Internet Passwords (authenticated only)
#http-huawei-hg5xx-vuln: Detects Huawei modem models vulnerable to information disclosure vulnerabilities
#http-iis-short-name-brute: (DoS) brute force short names of files and dirs in the root folder of vulnerable IIS servers
#http-phpself-xss: Crawls for php and texts XSS via
#http-slowloris-check: (DoS) Checks if vulnerable to Slowloris
#http-slowloris: (DoS) Execute a slowloris attack
#http-stored-xss: Spiders forms, posts, and searches for stored XSS
#http-tplink-dir-traversal: Exploit dirTrav in TP-Link wireless routers
#http-vuln-cve2011-3192: Denial of service against Apache handling multiple overlapping/simple ranges of a page
#http-vuln-cve2013-6786: URL redirection and reflected XSS vuln in Allegro RomPager
#http-vuln-cve2014-2129: Cisco ASA DoS
#tls-ticketbleed: Detects vulnerable to F5 Ticketbleed (CVE-2016-9244)

def standardNmapHTTP(ip_address, port):
    print "INFO: Performing nmapHttpVulns script scans for %s:%s" % (ip_address, port)
    results = subprocess.check_output(['nmap','-n','-sV','-Pn','-p',port,'--script=http-adobe-coldfusion-apsa1301,http-awstatstotals-exec,http-axis2-dir-traversal,http-barracuda-dir-traversal,http-coldfusion-subzero,http-csrf,http-dombased-xss,http-drupal-enum-users,http-frontpage-login,http-iis-webdav-vuln,http-litespeed-sourcecode-download,http-majordomo2-dir-traversal,http-open-redirect,http-phpmyadmin-dir-traversal,http-vmware-path-vuln,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-1001000,http-vuln-cve2017-5638,http-vuln-cve2017-5689,http-vuln-cve2017-8917,http-vuln-misfortune-cookie,http-vuln-wnr1000-creds,vulners',ip_address,'-oA',outfile])
    return

#running
#http-shellshock.nse: Attempt to exploit CVE-2014-6271 and CVE-2014-7169 Shellshock vulnerability in web applications http-shellshock.uri=/
#http-sql-injection.nse: Very basic attempt to show SQL errors in forms. http-sql-injection.url=URLs relative to the scanned host ie /default.html
#for status 200 in urls if the file exists
def shellshockSQL(ip_address, port):
    # if os.path.isfile(STAT_200):
        # g = open(STAT_200)
    # elif os.path.isfile(STAT_200_SORTED):
        # g = open(STAT_200_SORTED)
    # else:
        # print "STATUS 200 URLS do not exist. Please create or run dirbEVERYTHING first"
        # return
    g = open(STAT_200)
    for item in g:
        item = item.split(" ")[0] #line is url [status ] etc, need to split
        if "\n" in item:
            item = item[:-1]
        nmapArg = item.split(port)[1]
        if nmapArg[0] != "/":
            nmapArg = "/" + nmapArg
        if '"' or "'" in nmapArg:
            continue #arg will could break out and error script
        results = subprocess.check_output(['nmap','-n','-sV','-Pn','-p',port,'--script=http-shellshock,http-sql-injection','--script-args',"http-sql-injection.url='%s',http-shellsock.uri='%s'" % (nmapArg,nmapArg),ip_address,'-oA',outfile2])
        f.write("URL " + nmapArg + "\n")
        f.write(results)
    g.close()
    return


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle enumeration of specific web vulnerabilities. A list of (valid) URLs should be used. Usage: webRecon.py URL_List <http(s)://target_url:port>')
    parser.add_argument('URL_List',help='This should be a file of valid (preferably status 200) URLs')
    parser.add_argument('url', help='This should be the target URL in http(s)://URL:PORT format')

    args=parser.parse_args()

    #Fix URL if "http(s)" is not pased in
    if len(args.url.split(":")) == 0 or len(args.url.split(":")) == 1:
        print "Need to specify URL:PORT"
        sys.exit(1)
    elif ("https" in args.url):
        tmp = args.url.split("https://")
        if len(tmp) == 2: #https:// and IP:port
            if len(tmp[1].split(":")) == 2:
                ip_address = tmp[1].split(":")[0]
                port = tmp[1].split(":")[1]
            else:
                print "Need to specify URL:PORT"
                sys.exit(1)
    elif ("http" in args.url):
        tmp = args.url.split("http://")
        if len(tmp) == 2:
            if len(tmp[1].split(":")) == 2:
                ip_address = tmp[1].split(":")[0]
                port = tmp[1].split(":")[1]
            else:
                print "Need to specify URL:PORT"
                sys.exit(1)
    else:
        tmp = args.url.split(":")
        if len(tmp) == 2:
            ip_address = tmp[0]
            port = tmp[1]

    BASE = "/root/scripts/recon_enum/results/exam/http"
    DIRB_BASE = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port) #WARNING THIS CHANGES AFTER dirbustEVERYTHING SORTS INTO FOLDER
    STAT_200 = args.URL_List
    #STAT_200 = "%s/stat200_%s_%s" % (DIRB_BASE, ip_address, port) #ip_address is typically used (by defaut), but a user can specify
    #STAT_200_SORTED = "%s/%s/stat200_%s_%s" % (DIRB_BASE,ip_address,ip_address,port)
    outfile = "%s/%s_%s_nmap_HttpVulns.txt" % (BASE, ip_address, port)
    outfile2 = "%s/%s_%s_nmap_HttpVulns_SS_SQL.txt" % (BASE, ip_address, port)


    standardNmapHTTP(ip_address, port)
    shellshockSQL(ip_address, port)
    # while not os.path.isfile(STAT_200) and not os.path.isfile(STAT_200_SORTED):
        # time.sleep(5)
    # else:
        # shellshockSQL(ip_address, port)
        # print "INFO: nmapHttpVulns complete"

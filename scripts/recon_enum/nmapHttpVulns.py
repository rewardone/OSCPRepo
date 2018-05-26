#!/usr/bin/env python

import sys
import os
import subprocess
import errno
import time
import multiprocessing
from multiprocessing import Process

def help():
    print "Usage: nmapHttpVulns.py <ip address> <port>"
    sys.exit(0)

if len(sys.argv) < 2:
    help()

def mkdir_p(path):
   try:
      os.makedirs(path)
   except OSError as exc: #Python >2.5
      if exc.errno == errno.EEXIST and os.path.isdir(path):
         pass
      else:
         raise

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#This is needed in case of odd ports. May not be only 80/443
#path = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
path = "/root/scripts/recon_enum/results/exam/http"
#mkdir_p(path)

BASE = "/root/scripts/recon_enum/results/exam/http"
DIRB_BASE = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port) #WARNING THIS CHANGES AFTER dirbustEVERYTHING SORTS INTO FOLDER
STAT_200 = "%s/stat200_%s_%s" % (DIRB_BASE, ip_address, port) #ip_address is typically used (by defaut), but a user can specify
STAT_200_SORTED = "%s/%s/stat200_%s_%s" % (DIRB_BASE,ip_address,ip_address,port)
outfile = "%s/%s_%s_nmap_HttpVulns.txt" % (BASE, ip_address, port)
f = open(outfile, "a")

#running
#http-vuln-cve2006-3392.nse: Webmin before 1.290 and Usermin before 1.220 file disclosure using %01
#http-vuln-cve2009-3960.nse: Adobe XML External Entity Injection. Read local files in BlazeDS <3.2, LiveCycle 8.0.1 8.2.1 and 9, LiveCycleData Services 2.5.1 2.6.1 and 3, Flex Data Service 2.0.1 and ColdFusion 7.0.2 8.0 8.0.1 and 9.0
#http-vuln-cve2010-0738.nse: JBoss target is vulnerable to JMX console auth bypass via HEAD request
#http-vuln-cve2010-2861.nse: Dir trav against ColdFusion to grab password hash for admin, use hidden salt to crate SHA1 hash and authenticate as admin (ColdFusion pass the hash)
#http-vuln-cve2011-3368.nse: Reverse Proxy Bypass vuln in Apache. Loopback test, internal hosts test,  external website test
#http-vuln-cve2012-1823.nse: PHP-CGI installations that are vuln to this cve. Retrieve source code and execute code. append multiple ?
#http-vuln-cve2013-0156.nse: Ruby on Rails object injection, remote command exec, and DoS. All Ruby < 2.3.15, 3.0.x - 3.0.19, 3.1.x - 3.1.10, and 3.2.x - 3.2.11 are vuln. If 500 response, likely vulnerable
#http-vuln-cve2013-7091.nse: Zimbra 7.2.6 local file inclusion
#http-vuln-cve2014-2126.nse: Cisco ASA ASDM Priv Esc
#http-vuln-cve2014-2127.nse: Cisco ASA ASDM Priv Esc
#http-vuln-cve2014-2128.nse: Cisco ASA SSL VPN Auth bypass
#http-vuln-cve2014-3704.nse: Drupalgeddon < 7.32, injects new admin and attempt to log in
#http-vuln-cve2014-8877.nse: Wordpress CM Download Manager plugin <= 2.0.0 remote code injection
#http-vuln-cve2015-1427.nse: Elasticsearch 1.3.0-1.3.7 1.4.0-1.4.2 RCE in groovy
#http-vuln-cve2015-1635.nse: RCE in Windows Systems. HTTP request with no impact on the system to detect. Win 7,8,8.1 and server 2012,2012R2
#http-vuln-cve2017-1001000.nse: Wordpress 4.7.0 4.7.1 priv esc
#http-vuln-cve2017-5638.nse: Apache Struts RCE
#http-vuln-cve2017-5689.nse: Intel AMT priv esc
#http-vuln-cve2017-8917.nse: Joomla 3.7 - 3.7.1 SQLi
#http-vuln-misfortune-cookie.nse: RomPager 4.07 Misfortune Cookie RCE
#http-vuln-wnr1000-creds.nse: WNR admin creds 1.0.260_60-0.86 and 1.0.2.54_60.0.82

#Not running
#http-vuln-cve2011-3192.nse: Denial of service against Apache handling multiple overlapping/simple ranges of a page
#http-vuln-cve2013-6786.nse: URL redirection and reflected XSS vuln in Allegro RomPager
#http-vuln-cve2014-2129.nse: Cisco ASA DoS
def standardNmapHTTP():
    print "INFO: Performing nmapHttpVulns script scans for %s:%s" % (ip_address, port)
    results = subprocess.check_output(['nmap','-n','-sV','-Pn','-p',port,'--script=banner,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,http-vuln-cve2014-2128,http-vuln-cve2014-3704,http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,http-vuln-cve2017-1001000,http-vuln-cve2017-5638,http-vuln-cve2017-5689,http-vuln-cve2017-8917,http-vuln-misfortune-cookie,http-vuln-wnr1000-creds,vulners',ip_address])
    f.write(results)

#running
#http-shellshock.nse: Attempt to exploit CVE-2014-6271 and CVE-2014-7169 Shellshock vulnerability in web applications http-shellshock.uri=/
#http-sql-injection.nse: Very basic attempt to show SQL errors in forms. http-sql-injection.url=URLs relative to the scanned host ie /default.html
#for status 200 in urls if the file exists
def shellshockSQL():
    if os.path.isfile(STAT_200):
        g = open(STAT_200)
    elif os.path.isfile(STAT_200_SORTED):
        g = open(STAT_200_SORTED)
    else:
        print "STATUS 200 URLS do not exist. Please create or run dirbEVERYTHING first"
        return
    for item in g:
        item = item.split(" ")[0] #line is url [status ] etc, need to split
        if "\n" in item:
            item = item[:-1]
        nmapArg = item.split(port)[1]
        if nmapArg[0] != "/":
            nmapArg = "/" + nmapArg
        results = subprocess.check_output(['nmap','-n','-sV','-Pn','-p',port,'--script=http-shellshock,http-sql-injection','--script-args',"http-sql-injection.url='%s',http-shellsock.uri='%s'" % (nmapArg,nmapArg),ip_address])
        f.write("URL " + nmapArg + "\n")
        f.write(results)
    g.close()

standardNmapHTTP()
if not os.path.isfile(STAT_200) and not os.path.isfile(STAT_200_SORTED):
    time.sleep(5)
else:
    shellshockSQL()
    f.close()
    print "INFO: nmapHttpVulns complete"

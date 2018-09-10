#!/usr/bin/env python
import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse

#NSE Documentation
#Running
#dns-cache-snoop: Performs DNS cache snooping against DNS                       dns-cache-snoop.mode=timed,dns-cache-snoop.domains={host1,host2,host3}
#dns-check-zone: Checks DNS zone config against best practices                  dns-check-zone.domain=example.com
#dns-ip6-arpa-scan: Performs reverse lookup of IPv6 using special technique     prefix=2001:0DB8::/48
#dns-nsec-enum: Enumerate DNS using the DNSSEC NSEC-walking technique           dns-nsec-enum.domains=example.com
#dns-nsec3-enum: Tries to enum domain names from DNS server that supports DNSSEC NSEC3  dns-nsec3-enum.domains=example.com
#dns-nsid: Retrieves information from DNS by requesting nameserver
#     ID and asking for its id.server and version.bind values
#dns-random-srcport: Check DNS for predictable-port recursion Vuln
#dns-random-txid: Check DNS for predictable TXID DNS recursion Vuln
#dns-recursion: Checks if DNS allows queries for third-party names
#dns-service-discovery: Attempts to discover target hosts services using DNS
#dns-srv-enum: Enumerates various common SRV records for a given domain name    dns-srv-enum.domain='example.com'
#dns-update: Perform dynamic DNS update without authentication                  dns-update.hostname=foo.example.com,dns-update.ip=192.0.2.1
#dns-zone-transfer: Requests a zone transfer from DNS server
#                                                                               dns-zone-transfer.domain
#                                                                               dns-zone-transfer.server
#                                                                               dns-zone-transfer.port
#whois-domain: Queries whois.iana.org,

#Not running
#dns-blacklist: Checks target IP addresses against multiple DNS anti-spam and other lists
#dns-brute: Enum DNS by brute force
#dns-client-subnet-scan: Perform domain lookup using the edns-client-subnet option
#dns-fuzz: Launch DNS fuzzing attack against DNS
#dns-zeustracker: Check if IP range is part of Zeus

def doDNSNmapTCP():
    print "INFO: Starting nmap dnsrecon for %s and TCP %s" % (ip_address, port)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sT','-p',port,'--script','dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain','--script-args','dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=%s' % (domain, domain, domain, domain, domain),'-oA','%s/%s_dns_TCP' % (BASE, ip_address),ip_address])
    print "INFO: Finished nmap dnsrecon for %s and TCP %s" % (ip_address, port)
    return

def doDNSNmapUDP():
    print "INFO: Starting nmap dnsrecon for %s and UDP %s" % (ip_address, port)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sU','-p',port,'--script','dns-cache-snoop,dns-check-zone,dns-ip6-arpa-scan,dns-nsec-enum,dns-nsec3-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-srv-enum,dns-update,dns-zone-transfer,whois-domain','--script-args','dns-check-zone.domain=%s,dns-nsec-enum.domains=%s,dns-nsec3-enum-domains=%s,dns-srv-enum.domain=%s,dns-zone-transfer.domain=%s' % (domain, domain, domain, domain, domain),'-oA','%s/%s_dns_UDP' % (BASE, ip_address),ip_address])
    print "INFO: Finished nmap dnsrecon for %s and UDP %s" % (ip_address, port)
    return

# def doNMBLookup():
#     HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address) #grab the hostname
#     host = subprocess.check_output(HOSTNAME, shell=True).strip()
#     print "INFO: Attempting Domain Transfer on " + host
#     ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
#     ztresults = subprocess.check_output(ZT, shell=True)
#     if "failed" in ztresults:
#         print "INFO: Zone Transfer failed for " + host
#     else:
#         print "[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
#         outfile = "results/exam/" + ip_address+ "_zonetransfer.txt"
#         dnsf = open(outfile, "w")
#         dnsf.write(ztresults)
#         dnsf.close

# another approach using 'host' command:
# for server in $(host -t ns $1 |cut -d" " -f4);do
# # ForEach: attempt zone transfer
# host -l $1 $server | grep "has address"

#simplest approac is probably just calling /usr/bin/dnsrecon -d <domain> -t axfr

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

    parser = argparse.ArgumentParser(description='Rough script to handle simple dns enumeration. Usage: dnsrecon.py {--domain} target')
    parser.add_argument('target', help="Target IP")
    parser.add_argument('--domain', help="Target Domain")
    parser.add_argument('--port', default='53', help= "Port, default 53")

    args = parser.parse_args()

    ip_address = args.target
    port = args.port
    domain = args.domain

    BASE = '/root/scripts/recon_enum/results/exam/dns'
    mkdir_p(BASE)

    doDNSNmapTCP()
    doDNSNmapUDP()

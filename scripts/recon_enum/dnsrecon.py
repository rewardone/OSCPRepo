#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: dnsrecon.py <ip address>"
    sys.exit(0)

ip_address = sys.argv[1]


HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname         
host = subprocess.check_output(HOSTNAME, shell=True).strip()
print "INFO: Attempting Domain Transfer on " + host
ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
ztresults = subprocess.check_output(ZT, shell=True)
if "failed" in ztresults:
    print "INFO: Zone Transfer failed for " + host
else:
    print "[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
    outfile = "results/exam/" + ip_address+ "_zonetransfer.txt"
    dnsf = open(outfile, "w")
    dnsf.write(ztresults)
    dnsf.close

#NSE Documentation
#Running
#dns-zone-transfer: requests a zone transfer (AXFR) from a DNS server
#dns-brute: attempt to brute force common subdomains. 
#dns-cache-snoop: perform DNS cache snooping. Two modes controlled by dns-cache-snoop.mode arg. Default list checks top 50 more popular site. dns-cache-snoop.domains arg to use different list.
#dns-check-zone: check zone config against best practices.
#dns-ip6-arpa-scan: performs reverse DNS lookup of an IPv6 network using a technique which reduces number of queries needed to enumerate large networks.
#dns-nsec-enum: enumerate DNS names using DNSSEC NSEC-walking technique
#dns-nsec3-enum: Enum domain names from DNS server that supports DNSSEC NSEC3 records
#dns-nsid: retrieves information from a DNS nameserver by requesting its namesrver ID (nsid) and asking for its id.server and version.bind values. similar to 'dig CH TXT bind.version @target' and 'dig +nsid CH TXT id.server @target'
#dns-random-srcport: checks DNS for predictable-port recursion vulnerability. Predictable source ports make DNS vulnerable to cache poisoning.
#dns-random-txid: checks if vuln to predictable-TXID DNS recursion. Can make DNS vuln to cache poisoning. 
#dns-srv-enum: enum various SRV records for a given domain name.


#Not running
#dns-blacklist: checks IP addresses against multiple DNS anti-spam and open proxy blacklists, returns why flagged
#dns-client-subnet-scan: perform lookup using edns-client-subnet option. Enumerate as many different address records as possible.
#dns-fuzz: launches fuzzing against DNS servers. 
#dns-recursion: checks if DNS allows queries for thrid-party names.
#dns-service-discovery: attempts to discover target hosts' services using DNS service discovery protocol
#dns-update: attempt dynamic DNS update without authentication
#dns-zeustracker: checks if target IP range is part of Zues botnet by querying ZTDNS @ abuse.ch

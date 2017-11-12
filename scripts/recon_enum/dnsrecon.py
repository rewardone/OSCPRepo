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


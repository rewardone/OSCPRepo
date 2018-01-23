#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

#NSE Documentation
#Running
#snmp-brute: Attempt to find community string by brute force guessing. default wordlist: nselib/data/snmpcommunities.lst. provide own with snmp-brute.communitiesdb arg
#snmp-hh3c-logins: Attempts to enum Huawei / HP/H3c Locally defined users through the hh3c-user.mib OID. --script-args creds.snmp=:<community>
#snmp-info: extract basic information from SNMPv3 GET request
#snmp-ios-config: attempt to download CISCO router IOS config files using SNMP RW (v1) and display or save them --script-args creds.snmp=:<community>
#snmp-netstat: attempt to query for netstat like output. Can be used to identify and add new targets to scan by using newtargets script arg.
#snmp-processes: attempt to enumerate running processes through SNMP
#snmp-sysdescr: attempt to extract system information from SNMP v1 service
#snmp-win32-services: attempt to enumerate windows services through SNMP
#snmp-win32-shares: attempt to enumerate windows shares through SNMP
#snmp-win32-software: attempt to enumerate installed software through SNMP
#snmp-win32-users: attempt to enumerate winodws users accounts through SNMP

#Not running
#snmp-interfaces: attempts to enum nework interfaces through SNMP. snmp-interfaces.host arg is required  

print "INFO: Performing nmap SNMP script scan for " + ip_address + ":161,162"
SNMPSCAN = "nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -oN '/root/scripts/recon_enum/results/exam/snmp/%s_snmp.nmap' %s" % (ip_address)
results = subprocess.check_output(SNMPSCAN, shell=True)
resultsfile = "/root/scripts/recon_enum/results/exam/snmp/" + ip_address + "_snmprecon.txt"
f = open(resultsfile, "w")
f.write(results)
f.close

## TODO FIX ME ##
#onesixtyone requires a community string or a list of community names to try

ONESIXONESCAN = "onesixtyone %s" % (ip_address)
results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

if results != "":
    if "Windows" in results:
        results = results.split("Software: ")[1]
        snmpdetect = 1
    elif "Linux" in results:
        results = results.split("[public] ")[1]
        snmpdetect = 1
    if snmpdetect == 1:
        print "[*] SNMP running on " + ip_address + "; OS Detect: " + results
        SNMPWALK = "snmpwalk -c public -v1 %s 1 > results/%s_snmpwalk.txt" % (ip_address, ip_address)
        results = subprocess.check_output(SNMPWALK, shell=True)
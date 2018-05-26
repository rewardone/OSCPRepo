#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: snmprecon.py <ip address>"
    sys.exit(0)

snmpdetect = 0
ip_address = sys.argv[1]

# -c <communityfile> file with community names to try
# -i <inputfile> file with target hosts
# -o <outputfile> output log
# -d debug mode, use twice for more information
# -w n wait n milliseconds (1/1000 of a second) between sending packets (default 10)
# -q quiet mode, do not print log to stdout, use with -l
def onesixtyone():
    #snmp_all_communities is from seclists with 3250 strings
    communities_found = []
    SNMP_COMMUNITY_STRINGS = "/root/lists/snmp_all_communities.txt"
    print "INFO: Performing onesixtyone brute for %s:161" % (ip_address)
    #ONESIXONESCAN = "onesixtyone %s -c %s -o /root/scripts/recon_enum/results/exam/snmp/%s_onesixtyone" % (ip_address, SNMP_COMMUNITY_STRINGS)
    #results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()
    results = subprocess.check_output(['onesixtyone',ip_address,'-c',SNMP_COMMUNITY_STRINGS,'-o','/root/scripts/recon_enum/results/exam/snmp/%s_%s_onesixtyone' % (ip_address,port)])
    if results != "":
        for result in results:
            if "[" and "]" in result:
                communities_found.append(result.split("[")[1].split("]")[0])
    if len(communities_found) != 0:
        return communities_found
    else:
        return False

#NSE Documentation
#Running
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
#snmp-brute: Attempt to find community string by brute force guessing. default wordlist: nselib/data/snmpcommunities.lst. provide own with snmp-brute.communitiesdb arg
def nmap_communities(communities):
    for community in communities:
        print "INFO: Performing nmap SNMP script scan for %s:161 and community %s" % (ip_address, community)
        #SNMPSCAN = "nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners --script-args creds.snmp=:%s -oA '/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmp.nmap' %s" % (community, ip_address, community)
        subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sU','-p',port,'161,162','--script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners','--script-args',"creds.snmp=:%s" % community,'-oA','/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmp.nmap' % (ip_address,community),ip_address])
        #results = subprocess.check_output(SNMPSCAN, shell=True)
        # resultsfile = "/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmprecon.txt" % (ip_address, community)
        # f = open(resultsfile, "w")
        # f.write(results)
        # f.close

def nmap():
    print "INFO: Performing nmap SNMP script scan for %s:161,162 and NO COMMUNITY" % (ip_address)
    #SNMPSCAN = "nmap -n -vv -sV -sU -Pn -p 161,162 --script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners -oA '/root/scripts/recon_enum/results/exam/snmp/%s_snmp.nmap' %s" % (ip_address)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sU','-p',port,'161,162','--script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners','-oA','/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmp.nmap' % (ip_address,port),ip_address])
    #results = subprocess.check_output(SNMPSCAN, shell=True)
    # resultsfile = "/root/scripts/recon_enum/results/exam/snmp/%s_snmprecon.txt" % (ip_address)
    # f = open(resultsfile, "w")
    # f.write(results)
    # f.close

# script_version     = 'v1.8'; written in perl
# Usage ./$name -t <IP address>\n
#-t : target host;
#-p : SNMP port; default port is $port;
#-c : SNMP community; default is $community;
#-v : SNMP version (1,2); default is $snmpver;
#-r : request retries; default is $retries;
#-w : detect write access (separate action by enumeration);
#-d : disable 'TCP connections' enumeration!
#-T : force timeout in seconds; default is $timeout. Max is 60;
#-D : enable debug;
#-h : show help menu;\n\n

# script_version     = 'v1.9'; written in ruby
# script_usage = " Usage: #{script_name} [OPTIONS] <target IP address>\n
# -p --port        : SNMP port. Default port is 161;
# -c --community   : SNMP community. Default is public;
# -v --version     : SNMP version (1,2c). Default is 1;\n
# -w --write       : detect write access (separate action by enumeration);\n
# -d --disable_tcp : disable TCP connections enumeration!
# -t --timeout     : timeout in seconds. Default is 5;
# -r --retries     : request retries. Default is 1;
# -i --info        : show script version;
# -h --help        : show help menu;\n\n"
def snmp_check(communities):
    print "INFO: Performing nmap SNMP script scan for %s:161 and found communit(y|ies)" % (ip_address)
    #version check is in place just in case. 1.8 requires -t for target while 1.9 does not.
    #1.9 should be installed for default installations
    #versionInfo = "snmp-check -h"
    #version = subprocess.check_output(versionInfo, shell=True)
    version = subprocess.check_output(['snmp-check','-h'])
    if "v1.8" in version:
        for community in communities:
            #SNMPCHECK = "snmp-check -c %s -t %s > /root/scripts/recon_enum/results/exam/snmp/%s_%s_snmpcheck" % (community, ip_address, ip_address, community)
            #results = subprocess.check_output(SNMPSCAN, shell=True)
            outfile = "/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmpcheck" % (ip_address,community)
            results = subprocess.check_output(['snmp-check','-c',community,'-t',ip_address])
            if results:
                f = open(outfile,'w')
                for res in results:
                    f.write(res)
                f.close()
    if "v1.9" in version:
        for community in communities:
            #SNMPCHECK = "snmp-check -c %s %s > /root/scripts/recon_enum/results/exam/snmp/%s_%s_snmpcheck" % (community, ip_address, ip_address, community)
            #results = subprocess.check_output(SNMPSCAN, shell=True)
            outfile = "/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmpcheck" % (ip_address,community)
            results = subprocess.check_output(['snmp-check','-c',community,ip_address])
            if results:
                f = open(outfile,'w')
                for res in results:
                    f.write(res)
                f.close()
    return True

communities = onesixtyone()
if communities:
    nmap_communities(communities)
    snmp_check(communities)
else:
    nmap()
print "INFO: SNMPrecon complete. If communities were found and you want more information than snmp-check, please query snmpwalk manually"

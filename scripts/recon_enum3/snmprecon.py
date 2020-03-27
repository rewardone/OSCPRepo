#!/usr/bin/env python
import subprocess
import sys
import argparse
import pathlib

# TODO requires list of snmp communities to be in the right place

#if "#mibs :" not in /etc/snmp/snmp.conf
#print: You can 'apt install snmp-mibs-downloader', comment /etc/snmp/snmp.conf, and get human readble SNMP output
snmpdetect = 0


# -c <communityfile> file with community names to try
# -i <inputfile> file with target hosts
# -o <outputfile> output log
# -d debug mode, use twice for more information
# -w n wait n milliseconds (1/1000 of a second) between sending packets (default 10)
# -q quiet mode, do not print log to stdout, use with -l
def onesixtyone():
    #snmp_all_communities is from seclists with 3250 strings
    print("INFO: Performing onesixtyone brute for %s:161" % (ip_address))
    results = subprocess.check_output(['onesixtyone','-o',ONESIXTYONE_RESULTS,ip_address,'-c',SNMP_COMMUNITY_STRINGS],encoding='utf8')
    if results != "":
        return True
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
def nmap_communities(community):
    print("INFO: Performing nmap SNMP script scan for %s:161 and community %s" % (ip_address, community))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sU','-p','%s' % port,'--script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners','--script-args',"creds.snmp=:%s" % community,'-oA','%s/%s_%s_snmp.nmap' % (BASE,ip_address,community),ip_address],encoding='utf8')


def nmap():
    print("INFO: Performing nmap SNMP script scan for %s:161,162 and NO COMMUNITY" % (ip_address))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-sU','-p',port,'161,162','--script=snmp-brute,snmp-hh3c-logins,snmp-info,snmp-ios-config,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users,vulners','-oA','%s/%s_%s_snmp.nmap' % (BASE,ip_address,port),ip_address],encoding='utf8')


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
def snmp_check(community):
    print("INFO: Performing SNMP_check for %s:161 and found communit(y|ies)" % (ip_address))

    snmp18_1_outfile = "%s/%s_%s_snmpcheck_v1" % (BASE,ip_address,community)
    snmp18_2_outfile = "%s/%s_%s_snmpcheck_v2" % (BASE,ip_address,community)
    snmp19_1_outfile = "%s/%s_%s_snmpcheck_v1" % (BASE,ip_address,community)
    snmp19_2_outfile = "%s/%s_%s_snmpcheck_v2c" % (BASE,ip_address,community)

    #version check is in place just in case. 1.8 requires -t for target while 1.9 does not.
    #1.9 should be installed for default installations

    version = subprocess.check_output(['snmp-check','-h'],encoding='utf8')
    if "v1.8" in version:
        results = subprocess.check_output(['snmp-check','-v','1','-c',community,'-w','-t',ip_address],encoding='utf8')
        if results:
            f = open(snmp18_1_outfile,'w')
            for res in results:
                f.write(res)
            f.close()
            snmpwalk("1", community)
        results = subprocess.check_output(['snmp-check','-v','2','-c',community,'-w','-t',ip_address],encoding='utf8')
        if results:
            f = open(snmp18_2_outfile,'w')
            for res in results:
                f.write(res)
            f.close()
            snmpwalk("2c", community)
    if "v1.9" in version:
        results = subprocess.check_output(['snmp-check','-v','1','-c',community,'-w',ip_address],encoding='utf8')
        if results:
            f = open(snmp19_1_outfile,'w')
            for res in results:
                f.write(res)
            f.close()
            snmpwalk("1", community)
        results = subprocess.check_output(['snmp-check','-v','2c','-c',community,'-w',ip_address],encoding='utf8')
        if results:
            f = open(snmp19_2_outfile,'w')
            for res in results:
                f.write(res)
            f.close()
            snmpwalk("2c", community)
    return True


#  -v 1|2c|3             specifies SNMP version to use
#  -V, --version         display package version number
#SNMP Version 1 or 2c specific
#  -c COMMUNITY          set the community string
#SNMP Version 3 specific
#  -a PROTOCOL           set authentication protocol (MD5|SHA)
#  -A PASSPHRASE         set authentication protocol pass phrase
#  -e ENGINE-ID          set security engine ID (e.g. 800000020109840301)
#  -E ENGINE-ID          set context engine ID (e.g. 800000020109840301)
#  -l LEVEL              set security level (noAuthNoPriv|authNoPriv|authPriv)
#  -n CONTEXT            set context name (e.g. bridge1)
#  -u USER-NAME          set security name (e.g. bert)
#  -x PROTOCOL           set privacy protocol (DES|AES)
#  -X PASSPHRASE         set privacy protocol pass phrase
#  -Z BOOTS,TIME         set destination engine boots/time
#TODO only snmp v1/v2c supported at this time!
def snmpwalk(version, community):
    print("Walking with snmpwalk")
    outfile = "/root/scripts/recon_enum/results/exam/snmp/%s_%s_snmpwalk_%s" % (ip_address, community, version)
    results = subprocess.check_output(['snmpwalk','-c',community,'-v',version,ip_address])
    if results:
        f = open(outfile, 'w')
        for res in results:
            f.write(res)
        f.close()

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking SNMP endpoints. Usage: snmprecon.py <ip address>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = 161
    
    BASE = '/root/scripts/recon_enum/results/exam/snmp'
    mkdir_p(BASE)

    SNMP_COMMUNITY_STRINGS = "/root/lists/snmp_all_communities.txt"
    ONESIXTYONE_RESULTS = '%s/%s_%s_onesixtyone' % (BASE,ip_address,port)

    communities = onesixtyone()
    if communities:
        print("Communities found! Passing to nmap and snmp_check")
        f = open(ONESIXTYONE_RESULTS,'r')
        for community in f:
            if "[" and "]" in community:
                community = community.split("[")[1].split("]")[0]
            nmap_communities(community)
            snmp_check(community)
        f.close()
    else:
        nmap()
    print("INFO: SNMPrecon complete. If communities were found and you want more information than snmp-check, please query snmpwalk manually")
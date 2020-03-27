#!/usr/bin/python
import sys
import subprocess
import os
import errno
import multiprocessing
from multiprocessing import Process
import argparse
import pathlib

# TODO add ability for password authentication
# TODO some of these functions can be replaced with CME or smbmap or something else, reduce total number of dependencies,
#    External dependencies are nullinux and nbtscan-unixwiz

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

#NSE Documentation
#Running
#smb-double-pulsar-backdoor: check if target is running Double Pulsar SMB backdoor
#smb-enum-domains: attempt to enum domains on a system with policies. generally requires creds.
#smb-enum-groups: obtain a list of grous from remote system as well as a list of groups users. Works similar to 'enum.exe /g'
#smb-enum-processes: pull list of processes from remote server over SMB. Done by query remote registry service. disabled by default on Vista. Requires Admin on others.
#smb-enum-sessions: enumerate users logged in locally or through share. reading remote registry (Vista disabled by default). Requires higher than 'anonymous'
#smb-enum-shares: attempt to list shares using srvsvc.NetShareEnumAll MSRPC and NetShareGetInfo. NetShareGetInfo requires Admin
#mb-enum-users: attempt to enum users on remote system through MSRPC over 445 or 139. SAMR enum and LSA brute.
#smb-ls: attempts to retrieve useful information about files shared on SMB volumes. Resemble output of 'ls' command
#smb-os-discovery: attempt to determine OS, computer name, domain, workgroup, and current time over SMB. anonymous.
#smb-protocols: attempts to initiate a connection using each version of SMB. if SMBv1 is found, it will mark it as insecure.
#smb-security-mode: returns information about the SMB security level determined by SMB, ie signing, challenge-response, etc
#smb-system-info: pulls info from registry. Requires Admin, though auth user should get some info.
#smb-vuln-cve-2017-7494: check if vuln to Arbitrary Shared Library Load vuln CVE-2017-7494. Unpatched Samba from 3.5.0-4.4.13 and prior to 4.5.10 and 4.6.4 are affected by RCE.
#smb-vuln-ms17-010: check if vuln to MS17-010 aka EternalBlue. Connects to $IPC tree, executes transaction and checks if error. SMBv1 vuln.
#smb-vuln-ms10-061: check if vuln to ms10-061 Printer Spooler impersonation. used in Stuxnet. Checks for vuln in safe way without crashing. Needs access to at least one shared printer.
#smb2-security-mode: determines mesage signing config in SMBv2 servers for all supported dialects.
#smb2-vuln-uptime: attempt to detect missing patches in windows sytems by checking the uptime returned during the SMB2 protocol negotiation
#samba-vuln-cve-2012-1182: RCE as root from anonymous connection
#nbstat: retrieve target's NetBIOS names and MAC

#Not running
#smb-brute: Attempt to guess login over SMB
#smb-enum-services: retries list of services running. Requires Admin. No longer default available.
#smb-flood: exhausts a remote SMB server's connection limit by opening as many as possible.
#smb-mbenum: queries information managed by the Windows Master Browser
#smb-print-text: attempt to print test on a shared printer by calling Printer Spooler Service RPC functions
#smb-psexec: arguably most powerful module. requires configuration. config places in /nselib/data/psexec. Read documentation. https://github.com/nmap/nmap/blob/master/scripts/smb-psexec.nse
#smb-server-stats: requires Admin. grab server stats.
#smb-vuln-conficker: Detects systems infected by conficker worm. dangerous check and may crash systems.
#smb-vuln-cve2009-3103: detects if vuln to DoS CVE-2009-3103. Will crash the service if it is vulnerable
#smb-vuln-ms06-025: check if vuln to MS06-025 RasRPCSubmitRequest RPC method
#smb-vuln-ms07-029: check if vuln to MS07-029 DNS RPC vulnerability. Will crash the service if vulnerable
#smb-vuln-ms08-067: check if vuln to MS08-067. Dangerous and may crash systems
#smb-vuln-ms10-054: check if vuln to MS10-054. Dangerous and will BSOD system
#smb-vuln-regsvc-dos: check if vuln to null pointer dereference in regsvc. Will crash service if vuln.
#smb2-capabilities: attempt to list supported cabilities in a SMBv2 server for each enabled dialect.
#smb2-time: attempt to obtain the current system date and start date of a SMB2 server
def doNmap():
    print("INFO: Performing nmap SMB script scan for %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-ls,smb-os-discovery,smb-protocols,smb-security-mode,smb-system-info,smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010,smb2-security-mode,smb2-vuln-uptime,samba-vuln-cve-2012-1182,nbstat,vulners','-oA',nmap_outfile,ip_address],encoding='utf8')

def doSAMR():
    print("INFO: Attempting unauthenticated samrdump scan for %s:%s" % (ip_address, port))
    try:
        results = subprocess.check_output(['samrdump.py',ip_address],encoding='utf8').split("\n")
        f = open(samr_outfile,'w')
        for res in results:
            f.write(res)
            if "\n" not in res:
                f.write("\n")
        f.close()
    except Exception as e:
        print(type(e))
        print("Unexpected issue in doSAMR in smbrecon")

#-va:   run verbosely and try all commands
#-U:    get userlist
#-M:    get machine list
#-S:    get sharelist
#-P:    get password policy information
#-G:    get group and member list
#-d:    be detailed, applies to -U and -S
#-a:    -USGProni
#-r:    RID cycle
#-l:    get limited info via LDAP 389 (DCs only)
#-o:    get OS information
#-i:    get printer information
#-n:    do an nmblookup
#-v:    Be verbose
def doEnum4Linux():
    print("INFO: Performing enum4linux scan for %s:%s" % (ip_address, port))
    try:
        results = subprocess.check_output(['enum4linux','-va',ip_address],encoding='utf8').split("\n")
        if results:
            f = open(enum4linux_outfile,'w')
            for res in results:
                f.write(res)
                if "\n" not in res:
                    f.write("\n")
            f.close()
    except subprocess.CalledProcessError:
        print("WARN: SMBrecon non-0 exit for %s, but should still write output" % (ip_address))

# usage: nbtscan-unixwiz [options] target [targets...]
# Targets are lists of IP addresses, DNS names, or address
# ranges. Ranges can be in /nbits notation ("192.168.12.0/24")
# or with a range in the last octet ("192.168.12.64-97")
# -V        show Version information
# -f        show Full NBT resource record responses (recommended)
# -H        generate HTTP headers
# -v        turn on more Verbose debugging
# -n        No looking up inverse names of IP addresses responding
# -p <n>    bind to UDP Port <n> (default=0)
# -m        include MAC address in response (implied by '-f')
# -T <n>    Timeout the no-responses in <n> seconds (default=2 secs)
# -w <n>    Wait <n> msecs after each write (default=10 ms)
# -t <n>    Try each address <n> tries (default=1)
# -P        generate results in perl hashref format
def doNbtscanUnixWiz():
    print("INFO: Performing nbtscan-unixwiz scan for %s:%s" % (ip_address, port))
    try:
        results = subprocess.check_output(['nbtscan-unixwiz','-f',ip_address],encoding='utf8').split("\n")
        f = open(nbtscanunixwiz_outfile,'w')
        for res in results:
            f.write(res)
            if "\n" not in res:
                f.write("\n")
        f.close()
    except Exception as e:
        print(type(e))
        print("Unexpected issue in doNbtscanUnixWiz in smbrecon")

# -shares             Dynamically Enumerate all possible shares. (formally: --enumshares)
# -users              Enumerate users through a variety of techniques. (formally: --enumusers)
# -quick              Quickly enumerate users, leaving out brute (used with: -users, or -all)
# -U                  Set username (optional)
# -P                  Set password (optional)
# -v                  Verbose Output
# -h                  Help menu
#https://github.com/m8r0wn/nullinux
def doNullLinux():
    print("INFO: Performing nullinux scan for %s:%s" % (ip_address, port))
    if os.path.isfile('/usr/local/bin/nullinux'):
        try:
            results = subprocess.check_output(['nullinux','-v',ip_address],encoding='utf8').split("\n")
            f = open(nullinux_outfile,'w')
            for res in results:
                f.write(res)
                f.write("\n")
            f.close()
        except Exception as e:
            print(type(e))
            print("Unexpected issue in doNullLinux in smbrecon")

def doSMBVer():
    #This is relevant for 'some' linux versions of smb. There are better ways to enumerate windows machines.
    print("INFO: Performing smbver check for %s" % (ip_address))
    results = subprocess.check_output(['./smbver.sh',ip_address],encoding='utf8')
    f = open(smbver_outfile,'w')
    for res in results:
        f.write(res)
        f.write("\n")
    f.close()


if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking SMB endpoints and available shares. Usage: smbrecon.py <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', help="Specific port to enumerate")
    args = parser.parse_args()

    BASE = "/root/scripts/recon_enum/results/exam/smb"
    mkdir_p(BASE)

    ip_address = args.ip_address 
    port = args.port
    nmap_outfile = "%s/%s_%s_smb" % (BASE,ip_address,port)
    samr_outfile = "%s/%s_%s_samrdump" % (BASE,ip_address,port)
    enum4linux_outfile = "%s/%s_%s_enum4linux" % (BASE,ip_address,port)
    nbtscanunixwiz_outfile = "%s/%s_%s_nbtscan-unixwiz" % (BASE,ip_address,port)
    nullinux_outfile = "%s/%s_%s_nullinux" % (BASE,ip_address,port)
    smbver_outfile = "%s/%s_%s_smbversion" % (BASE,ip_address, port)

    doNmap()
    doSAMR()
    doEnum4Linux()
    doNbtscanUnixWiz()
    doNullLinux()
    doSMBVer()
#!/usr/bin/python
import sys
import subprocess
import os
import errno
import multiprocessing
from multiprocessing import Process
import argparse

if len(sys.argv) != 3:
    print "Usage: smbrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1]
port = sys.argv[2].strip()

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

BASE = "/root/scripts/recon_enum/results/exam/smb"
mkdir_p(BASE)

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
print "INFO: Performing nmap SMB script scan for %s:%s" % (ip_address, port)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script=smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-ls,smb-os-discovery,smb-protocols,smb-security-mode,smb-system-info,smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010,smb2-security-mode,smb2-vuln-uptime,samba-vuln-cve-2012-1182,nbstat,vulners','-oA','/root/scripts/recon_enum/results/exam/smb/%s_%s_smb' % (ip_address,port),ip_address])

print "INFO: Performing samrdump scan for %s:%s" % (ip_address, port)
outfile = "/root/scripts/recon_enum/results/exam/smb/%s_%s_samrdump" % (ip_address,port)
results = subprocess.check_output(['samrdump.py',ip_address]).split("\n")
f = open(outfile,'w')
for res in results:
    f.write(res)
    if "\n" not in res:
        f.write("\n")
f.close()

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
print "INFO: Performing enum4linux scan for %s:%s" % (ip_address, port)
try:
    outfile = "/root/scripts/recon_enum/results/exam/smb/%s_%s_enum4linux" % (ip_address,port)
    results = subprocess.check_output(['enum4linux','-va',ip_address]).split("\n")
    if results:
        f = open(outfile,'w')
        for res in results:
            f.write(res)
            if "\n" not in res:
                f.write("\n")
        f.close()
except subprocess.CalledProcessError, e:
    print "WARN: SMBrecon non-0 exit for %s, but should still write output" % (ip_address)

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
print "INFO: Performing nbtscan-unixwiz scan for %s:%s" % (ip_address, port)
outfile = "/root/scripts/recon_enum/results/exam/smb/%s_%s_nbtscan-unixwiz" % (ip_address,port)
results = subprocess.check_output(['nbtscan-unixwiz','-f',ip_address]).split("\n")
f = open(outfile,'w')
for res in results:
    f.write(res)
    if "\n" not in res:
        f.write("\n")
f.close()

# -shares             Dynamically Enumerate all possible shares. (formally: --enumshares)
# -users              Enumerate users through a variety of techniques. (formally: --enumusers)
# -quick              Quickly enumerate users, leaving out brute (used with: -users, or -all)
# -all                Enumerate both users and shares (formally: --all)
# -U                  Set username (optional)
# -P                  Set password (optional)
# -v                  Verbose Output
# -h                  Help menu
#https://github.com/m8r0wn/nullinux
print "INFO: Performing nullinux scan for %s:%s" % (ip_address, port)
outfile = "/root/scripts/recon_enum/results/exam/smb/%s_%s_nullinux" % (ip_address,port)
results = subprocess.check_output(['nullinux.py','-v','-a',ip_address]).split("\n")
f = open(outfile,'w+')
for res in results:
    f.write(res)
    f.write("\n")
f.close()

print "INFO: Performing smbver check for %s" % (ip_address)
outfile = "/root/scripts/recon_enum/results/exam/smb/%s_%s_smbversion" % (ip_address, port)
results = subprocess.check_output(['./smbver.sh',ip_address])
f = open(outfile,'w+')
for res in results:
    f.write(res)
    f.write("\n")
f.close()

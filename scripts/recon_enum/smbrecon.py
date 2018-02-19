#!/usr/bin/python
import sys
import subprocess

if len(sys.argv) != 3:
    print "Usage: smbrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1]
port = sys.argv[2].strip()

#NSE Documentation
#Running
#smb-enum-domains: attempt to enum domains on a system with policies. generally requires creds. 
#smb-enum-groups: obtain a list of grous from remote system as well as a list of groups users. Works similar to 'enum.exe /g'
#smb-enum-processes: pull list of processes from remote server over SMB. Done by query remote registry service. disabled by default on Vista. Requires Admin on others.
#smb-enum-sessions: enumerate users logged in locally or through share. reading remote registry (Vista disabled by default). Requires higher than 'anonymous'
#smb-enum-shares: attempt to list shares using srvsvc.NetShareEnumAll MSRPC and NetShareGetInfo. NetShareGetInfo requires Admin
#mb-enum-users: attempt to enum users on remote system through MSRPC over 445 or 139. SAMR enum and LSA brute.
#smb-os-discovery: attempt to determine OS, computer name, domain, workgroup, and current time over SMB. anonymous.
#smb-protocols: attempts to initiate a connection using each version of SMB. if SMBv1 is found, it will mark it as insecure. 
#smb-system-info: pulls info from registry. Requires Admin, though auth user should get some info. 
#smb-vuln-cve-2017-7494: check if vuln to Arbitrary Shared Library Load vuln CVE-2017-7494. Unpatched Samba from 3.5.0-4.4.13 and prior to 4.5.10 and 4.6.4 are affected by RCE.
#smb-vuln-ms17-010: check if vuln to MS17-010 aka EternalBlue. Connects to $IPC tree, executes transaction and checks if error. SMBv1 vuln.
#smb-double-pulsar-backdoor: check if target is running Double Pulsar SMB backdoor
#smb2-vuln-uptime: attempt to detect missing patches in windows sytems by checking the uptime returned during the SMB2 protocol negotiation
#smb-ls: attempts to retrieve useful information about files shared on SMB volumes. Resemble output of 'ls' command
#smb-security-mode: returns information about the SMB security level determined by SMB, ie signing, challenge-response, etc
#smb2-security-mode: determines mesage signing config in SMBv2 servers for all supported dialects.
#smb-vuln-ms10-061: check if vuln to ms10-061 Printer Spooler impersonation. used in Stuxnet. Checks for vuln in safe way without crashing. Needs access to at least one shared printer.

#Not running
#smb-enum-services: retries list of services running. Requires Admin. No longer default available.
#smb-brute: Attempt to guess login over SMB
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

print "INFO: Performing nmap SMB script scan for " + ip_address + ":" + port
SMBSCAN = "nmap -n -sV -Pn -vv -p %s --script=smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-system-info,smb-vuln-cve-2017-7494,smb-vuln-ms17-010,smb-double-pulsar-backdoor,smb2-vuln-uptime,smb-ls,smb-security-mode,smb-vuln-ms10-061,smb2-security-mode,vulners -oN '/root/scripts/recon_enum/results/exam/smb/%s_%s_smb.nmap' %s" % (port, ip_address, port, ip_address)
results = subprocess.check_output(SMBSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/smb/" + ip_address + "_" + port + "_smbrecon.txt"
f = open(outfile, "w")
f.write(results)
f.close

NBTSCAN = "samrdump.py %s > /root/scripts/recon_enum/results/exam/smb/%s_%s_samrdump" % (ip_address, ip_address, port)
nbtresults = subprocess.check_output(NBTSCAN, shell=True)

ENUM4LINUXSCAN = "enum4linux %s > /root/scripts/recon_enum/results/exam/smb/%s_%s_enum4linux" % (ip_address, ip_address, port)
enum4linuxresults = subprocess.check_output(ENUM4LINUXSCAN, shell=True)

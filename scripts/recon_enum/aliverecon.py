#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import argparse

#nmap ping sends 0 data by default (detectable)
#TODO add options for --data <hex string>, --data-string <string>, or --data-length <number>


def alive_hosts(target_hosts):
    print "INFO: Performing ping sweep over %s" % (target_hosts)
    output_file = "/root/scripts/recon_enum/results/exam/targets.txt"
    f = open(output_file, 'w')
    if not os.path.isdir('/root/scripts/recon_enum/results/exam/nmap'):
        os.makedirs('/root/scripts/recon_enum/results/exam/nmap')
    lines = subprocess.check_output(['nmap','-n','-sn',target_hosts,'-oA','%s/%s_HOST_DISCOVERY' % (BASE,target_hosts)]).split("\n")
    live_hosts = 0
    for line in lines:
        line = line.strip()
        line = line.rstrip()
        if ("Nmap scan report for" in line):
            ip_address = line.split(" ")[4]
            if (live_hosts > 0):
                f.write('\n')
            f.write("%s" % (ip_address))
            live_hosts += 1
    print "INFO: Host scanning complete. Targets acquired."
    f.close()
    return

#NSE Documentation
#Running
#targets-ipv6-multicast-echo: Sends ICMPv6 echo to all nodes link local ff02::1 -script-args newtargets,interface=, may need -SL
#targets-ipv6-multicast-invalid-dst: Sends ICMPv6 with invalid extension to all nodes link-local (ff02::1) for Windows responses. --script-args 'newtargets,interface=', may need -sP
#targets-ipv6-multicast-mld: Sends multicast listener discovery to link-local (ff02::1), resp set to 1 to provoke immediate response. --script-args 'newtargets,interface='

#Not Running
#targets-asn: List of IP prefixes for a given routing AS number -script-args targets-asn.asn=
#targets-ipv6-map4to6: Runs in pre-scanning to map IPv4 to IPv6 and add them to scan. Lower 4 bytes of IPv6 are replaced with IPv4 address. --script-args targets-ipv6-map4to6.IPv4Hosts={},targets-ipv6-subnet={}
#targets-ipv6-multicast-slaac: Sends ICMPv6 router advertisement with random address prefix. Some hosts being SLAAC. --script-args 'newtargets,interface='
#targets-ipv6-wordlist: Adds IPv6 addresses to scan queue using wordlist of hexadecimal 'words' that form addresses in a given subnet. --script-args targets-ipv6-wordlist.wordlist,targets-ipv6-wordlists.nsegments,targets-ipv6-wordliss.fillright,targets-ipv6-subnet
def alive_hosts6(interface):
    print "INFO: Performing IPv6 pings and multicast"
    subprocess.check_output(['nmap','-6','-n','--script','targets-ipv6-multicast-echo,targets-ipv6-multicast-invalid-dst,targets-ipv6-multicast-mld','--script-args','interface=%s' % interface,'-oA','%s/%s_HOST_DISCOVERY_IPv6' % (BASE,interface)])
    print "INFO: Completed IPv6 pings and multicast. Add hosts to targets manually!!"
    return

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

    parser = argparse.ArgumentParser(description='Rough script to handle target aquisition. If interface is specified, nmap IPv6 will be done as well. Usage: aliverecon.py {-i interface} ip_range')
    parser.add_argument('ip_range', help="Range of target IPs. Typically last octect ranges: 10.10.10.0-255")
    parser.add_argument('-i', dest='interface', default="", help="Interface to enumate IPv6 on")

    args = parser.parse_args()
    #print args

    target_hosts = args.ip_range
    interface = args.interface

    BASE = '/root/scripts/recon_enum/results/exam/nmap'
    mkdir_p(BASE)

    alive_hosts(target_hosts)
    if interface != "":
        alive_hosts6(interface)

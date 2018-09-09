#!/usr/bin/env python
import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import argparse

#NSE Documentation
#Running
#broadcast-ataoe-discover: discover servers supporting ATA over ethernet. requires "-e <interface>"
#broadcast-bjnp-discover: Discover Canon (printer/scanner) supporting BJNP
#broadcast-db2-discover: attempt to discover DB2 servers on network by sending broadcast to UDP 523
#broadcast-dhcp-discover: send DHCP request to broadcast address and reports results
#broadcast-dhcp6-discover: send DHCPv6 request to multicast and prints address with any other options
#broadcast-dns-service-discovery: discover hosts' services using DNS Service Discovery Protocol
#broadcast-dropbox-listener: Listen for LAN sync Dropbox client broadcasts (already doing broadcast-listener)
#broadcast-eigrp-discovery: discover through CISCO's EIGRP, needs a A.S. value or will listen
#broadcast-igmp-discovery: Discovers targets that have IGMP Multicast memberships and grabs interesting information
#broadcast-listener: sniffs for broadcast communication and attempts to decode received packets, CDP, HSRP, Spotify, DropBox, DHCP, ARP and more
#broadcast-ms-sql-discover: broadcast version uses roadcast and only SQL Server Browser service discovery method.
#broadcast-netbios-master-browser: attempt to discovery master browser and the domains they manage
#broadcast-networker-discover: Discovers EMC Networker backup software servers by sending broadcast query
#broadcast-novell-locate: Attempts to use Service Location Protocol to discover Novell NetWare Core Protocol (NCP) servers
#broadcast-ospf2-discover: discover IPv4 network using OSPFv2, sniff for OSPF Hello packets and reply
#broadcast-pc-anywhere: sends a special broadcast to check for PC Anywhere hosts
#broadcast-pc-duo: Discovers PC-DUO remote control hosts and gateways by sending broadcast probe
#broadcast-pim-discovery: Discovers routers that are running PIM (protocol Independent Multicast)
#broadcast-ping: Sends broadcast pings and outputs responding hosts IP and MAC
#broadcast-pppoe-discover: Discovers PPPoE servers using PPPoE Discovery protocol
#broadcast-rip-discover: discover hosts and routing using RIPv2. Send RIPv2 Request and collects responses
#broadcast-ripng-discover: Discovers hosts and routing information from devices running RIPng
#broadcast-sonicwall-discover: Discovers Sonicwall firewalls using same method as manufacturers SetupTool
#broadcast-sybase-asa-discover: Discovers Sybase Anywhere Servers on LAN
#broadcast-tellstick-discover: Discovers Telldus Technologies TellStickNet
#broadcast-upnp-info: attempt to extract system information from UPnP service by sending multicast and collecting
#broadcast-versant-locate: Discovers Versant object databases using broadcast srvloc
#broadcast-wake-on-lan: Wakes a remote system from sleep using WoL packet
#broadcast-wpad-discover: Retrieve a list of proxy servers on lan using WPAD. Both DHCP and DNS methods.
#broadcast-wsdd-discover: multicast discover supporting Web Services Dynamic Discovery protocol.
#broadcast-xdmcp-discover: discovers servers running XDMCP
#url-snarf: Sniff interface for HTTP traffic and dumps URLs
#targets-sniffer: Sniff interface for IP addresses
#lltd-discovery: Use Microsoft LLTD protocol to discover hosts on a local network

#Not Running
#broadcast-avahi-dos: Exploits DoS
#broadcast-jenkins-discover:  #### DOES NOT EXIST ON KALI #### Discovers Jenkins on a LAN by sending a discovery broadcast probe
#broadcast-hid-discoveryd:  #### DOES NOT EXIST ON KALI #### Discovers HID devices by sending a discoveryd network broadcast probe
#llmnr-resolve: Resolve a hostname using LLMNR. Requires -script-arg llmnr-resolve.hostname=examplename
def doNmap(interface):
    print "INFO: Performing nmap broadcast discovery using interface: %s" % (interface)
    subprocess.check_output(['nmap','-vv','--script=broadcast-ataoe-discover,broadcast-bjnp-discover,broadcast-db2-discover,broadcast-dhcp-discover,broadcast-dhcp6-discover,broadcast-dns-service-discovery,broadcast-dropbox-listener,broadcast-eigrp-discovery,broadcast-igmp-discovery,broadcast-listener,broadcast-ms-sql-discover,broadcast-netbios-master-browser,broadcast-networker-discover,broadcast-novell-locate,broadcast-ospf2-discover,broadcast-pc-anywhere,broadcast-pc-duo,broadcast-pim-discovery,broadcast-ping,broadcast-pppoe-discover,broadcast-rip-discover,broadcast-ripng-discover,broadcast-sonicwall-discover,broadcast-sybase-asa-discover,broadcast-tellstick-discover,broadcast-upnp-info,broadcast-versant-locate,broadcast-wake-on-lan,broadcast-wpad-discover,broadcast-wsdd-discover,broadcast-xdmcp-discover,url-snarf,targets-sniffer,lltd-discovery','-oA','%s/%s_broadcast' % (BASE,interface),'-e',interface])
    print "INFO: Completed nmap broadcast discovery using interface: %s" % (interface)
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

    parser = argparse.ArgumentParser(description='Rough script to handle nmap broadcast recon scripts. Usage: broadcastrecon.py interface')
    parser.add_argument('interface', help="Interface to enumate/listen on")

    args = parser.parse_args()
    #print args

    interface = args.interface

    BASE = '/root/scripts/recon_enum/results/exam/nmap'
    mkdir_p(BASE)

    doNmap(interface)

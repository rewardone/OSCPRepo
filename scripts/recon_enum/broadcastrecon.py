#!/usr/bin/env python
import subprocess
import sys

if len(sys.argv) != 2:
    print "Usage: broadcastrecon.py <interface>"
    sys.exit(0)

interface = sys.argv[2]

#NSE Documentation
#Running
#broadcast-ataoe-discover: discover servers supporting ATA over ethernet. requires "-e <interface>"
#broadcast-db2-discover: attempt to discover DB2 servers on network by sending broadcast to UDP 523
#broadcast-dhcp-discover: send DHCP request to broadcast address and reports results
#broadcast-dhcp6-discover: send DHCPv6 request to multicast and prints address with any other options
#broadcast-dns-service-discover: discover hosts' services using DNS Service Discovery Protocol
#broadcast-listener: sniffs for broadcast communication and attempts to decode received packets, CDP, HSRP, Spotify, DropBox, DHCP, ARP and more
#broadcast-ms-sql-discover:broadcast version uses roadcast and only SQL Server Browser service discovery method. 
#broadcast-netbios-master-browser: attempt to discovery master browser and the domains they manage
#broadcast-ospf2-discover: discover IPv4 network using OSPFv2, sniff for OSPF Hello packets and reply
#broadcast-pc-anywhere: sends a special broadcast to check for PC Anywhere hosts
#broadcast-rip-discover: discover hosts and routing using RIPv2. Send RIPv2 Request and collects responses
#broadcast-upnp-info: attempt to extract system information from UPnP service by sending multicast and collecting
#broadcast-wsdd-discover: multicast discover supporting Web Services Dynamic Discovery protocol. 
#broadcast-xdmcp-discover: discovers servers running XDMCP
#targets-sniffer: sniffs local network for amount of time (10s default) and prints discovered addresses

#Not Running
#broadcast-eigrp-discover: discover through CISCO's EIGRP, needs a A.S. value or will listen
#broadcast-wpad-discover: Retrieve a list of proxy servers on lan using WPAD. Both DHCP and DNS methods.

print "INFO: Performing nmap broadcast discovery using interface: %s" % (interface)
DISCOVERYSCAN = "nmap -vv --script=broadcast-ataoe-discover,broadcast-db2-discover,broadcast-dhcp-discover,broadcast-dhcp6-discover,broadcast-dns-service-discover,broadcast-listener,broadcast-ms-sql-discover,broadcast-netbios-master-browser,broadcast-ospf2-discover,broadcast-pc-anywhere,broadcast-rip-discover,broadcast-upnp-info,broadcast-wsdd-discover,broadcast-xdmcp-discover,targets-sniffer -oN '/root/scripts/recon_enum/results/exam/nmap/%s_broadcast.nmap' -e %s" % (interface, interface)
results = subprocess.check_output(DISCOVERYSCAN, shell=True)
outfile = "/root/scripts/recon_enum/results/exam/nmap/%s_broadcastrecon.txt" % (interface)
f = open(outfile, "w")
f.write(results)
f.close
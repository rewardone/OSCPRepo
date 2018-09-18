#!/usr/bin/env python
import subprocess
import sys
import os

if len(sys.argv) != 3:
    print "Usage: msrpcrecon.py <ip address> <port>"
    sys.exit(0)

ip_address = sys.argv[1].strip()
port = sys.argv[2].strip()

#NSE Documentation
#Running
#msrpc-enum: Queries an MSRPC endoing mapper for a list of mapped services and displays the gathered information.
#   SMB library, so you can specify an optional username and password.
print "INFO: Performing nmap MSRPC script scan for %s:%s" % (ip_address, port)
#MSRPCSCAN = "nmap -n -sV -Pn -vv -p %s --script=msrpc-enum,vulners -oA '/root/scripts/recon_enum/results/exam/msrpc/%s_msrpc.nmap' %s" % (port, ip_address, ip_address)
#results = subprocess.check_output(MSRPCSCAN, shell=True)
subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','msrpc-enum,vulners','-oA','/root/scripts/recon_enum/results/exam/msrpc/%s_%s_msrpc.nmap' % (ip_address,port),ip_address])

#For interfaces listening on msrpc (select ports), do an ifmap
#IFMAPCMD = "ifmap.py %s %s" % (ip_address, port)
#results = subprocess.check_output(IFMAPCMD, shell=True)
#newlines = results.split("\n")
try:
    newlines = subprocess.check_output(['ifmap.py',ip_address,port]).split("\n")
    ifmap_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_ifdump.txt" % (ip_address, port)
    rawUUIDs = []
    f = open(ifmap_outfile, "w")
    for line in newlines:
        if ("UUID" in line):
            if ("other version listed" in line):
                rawUUIDs.append(line[11:-33])
            elif ("not listed" in line):
                rawUUIDs.append(line[11:-23])
            elif ("listed, listening" in line):
                rawUUIDs.append(line[11:-19])
        f.write(line)
        f.write("\n")
    f.close()
except:
    print "Something went wrong with ifmap on %s:%s, run manually" % (ip_address, port)

#Process the listening results from ifmap and get more information with opdump
access_denied=[]
success=[]
try:
    for UUID in rawUUIDs:
        scanme=UUID.split(" v")
        #OPDUMPSCAN = "opdump.py %s %s %s %s" % (ip_address, port, scanme[0], scanme[1])
        #results=subprocess.check_output(OPDUMPSCAN, shell=True)
        results = subprocess.check_output(['opdump.py',ip_address,port,scanme[0],scanme[1]])
        if ("rpc_s_access_denied" in results):
            access_denied.append(scanme[0] + " " + scanme[1])
            access_denied.append(results)
        else:
            success.append(scanme[0] + " " + scanme[1])
            success.append(results)
    denied_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_opdump_denied.txt" % (ip_address, port)
    f = open(denied_outfile, "w")
    for denied in access_denied:
        f.write(denied)
        f.write("\n")
    f.close()
except NameError:
    print "Unable to run opdump without ifmap"

#For success with opdump, reference the UID with limited additional information (offline)
success_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_opdump_success.txt" % (ip_address, port)
f = open(success_outfile, "w")
if success is not None:
    for good in success:
        tmp_uuid=good[:-4]
        if ":" not in good:
            for ifmap in newlines:
                if str(tmp_uuid) in ifmap:
                    tmp_uuid_index = newlines.index(ifmap)
                    tmp_protocol_index = tmp_uuid_index - 2
                    uuid=newlines[tmp_uuid_index]
                    if ("other version listed" in uuid):
                        f.write(uuid[11:-33])
                    elif ("not listed" in uuid):
                        f.write(uuid[11:-23])
                    elif ("listed, listening" in uuid):
                        f.write(uuid[11:-19])
                    f.write(" | ")
                    f.write(newlines[tmp_protocol_index])
                    f.write(good)
                    f.write("\n")
                    break
        else:
            f.write(good)
            f.write("\n")
    f.close()
else:
    print "Unable to run opdump on successful pipes"

#more information for kicks and giggles, no auth, but it supports Hash for SMB
rpcdump_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_rpcdump.txt" % (ip_address, port)
#RPCCMD = "rpcdump.py %s -port %s" % (ip_address, port)
#results = subprocess.check_output(RPCCMD, shell=True)
results = subprocess.check_output(['rpcdump.py',ip_address,'-port',port])
f = open(rpcdump_outfile, "w")
for res in results:
    f.write(res)
f.close()

print "This RPCDump is NOT authenticated, you must run manually"
print "\nINFO: MSRPCrecon Complete"

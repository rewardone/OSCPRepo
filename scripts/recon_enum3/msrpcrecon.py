#!/usr/bin/env python
import subprocess
import sys
import os
import pathlib
import argparse
import socket
import shutil

# RPCDump is an impacket script. This script will require python3-impacket to be installed, apt install python3-impacket is not enough. Must download and setup.py

# Patch to force ifmap to continue on timeout error instead of raising timeout errors
# can code this for dynamic check later on (grab the version out of /usr/local/bin/ifmap.py)
# but would need more checking around patching correctly
def patch_ifmap():
    #line 329: dce.connect()
    ifmap = '/usr/local/lib/python3.7/dist-packages/impacket-0.9.21.dev1+20200313.160519.0056b61c-py3.7.egg/EGG-INFO/scripts/ifmap.py'
    tmpmap = '/tmp/ifmap.py'
    sha256sum = 'ca54b5a010df84ef57e39143cb14d86343574ed22efb44b9c40b8a12c9558b4c' #orig file
    sha256sum_patched = '883d9d9085d67b010eb3ff63699a678101db95e597373b99029ca6d6be5c18ac' #patched
    if os.path.isfile(ifmap):
        sha_check = subprocess.run(['sha256sum',ifmap],check=True,stdout=subprocess.PIPE,encoding='utf8').stdout
        sha_check = sha_check.split(' ')[0]
        if sha_check == sha256sum_patched:
            return
        shutil.copy(ifmap,"%s.bak" % ifmap)
        sha_check = subprocess.run(['sha256sum',ifmap],check=True,stdout=subprocess.PIPE,encoding='utf8').stdout
        sha_check = sha_check.split(' ')[0]
        if sha_check == sha256sum:
            print("Patching ifmap")
            try:
                f = open(ifmap, 'r')
                g = open(tmpmap,'w+')
                for line in f:
                    if line == "    dce.connect()\n":
                        continue
                    elif line == "  for tup in sorted(probes):\n":
                        g.write(
"""  for tup in sorted(probes):
    try:
      dce.connect()
    except:
      continue""")
                    else:
                        g.write(line)
                f.close()
                g.close()
                shutil.move(tmpmap, ifmap)
            except:
                print("Unable to patch ifmap correctly.")
                shutil.move("%s.bak" % ifmap, ifmap)
        else:
            print("ifmap sha doesn't match orig or patched, not patching")


#NSE Documentation
#Running
#msrpc-enum: Queries an MSRPC endoing mapper for a list of mapped services and displays the gathered information.
#   SMB library, so you can specify an optional username and password.
def doNmap():
    print("INFO: Performing nmap MSRPC script scan for %s:%s" % (ip_address, port))
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','msrpc-enum,vulners','-oA','/root/scripts/recon_enum/results/exam/msrpc/%s_%s_msrpc.nmap' % (ip_address,port),ip_address],encoding='utf8')

#For interfaces listening on msrpc (select ports), do an ifmap
def doIFMap():
    print("Starting ifmap")
    if os.path.isfile("/usr/local/bin/ifmap.py"): #may be installed in other places?
        DEVNULL = open(os.devnull, 'w')
        ifmap_tmp = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_ifmap_tmp.txt" % (ip_address, port)
        ifmap_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_ifmap.txt" % (ip_address, port)
        ifmap_results_array = []
        try:
            ifmap_tmp_handle = open(ifmap_tmp,'w')
            subprocess.run(['ifmap.py',ip_address,port],encoding='utf8',stdout=ifmap_tmp_handle,stderr=DEVNULL)
            ifmap_tmp_handle.close()
            DEVNULL.close()
            rawUUIDs = []
            f = open(ifmap_outfile, "w")
            g = open(ifmap_tmp, "r")
            for line in g:
                if ("UUID" in line):
                    if ("other version listed" in line):
                        rawUUIDs.append(line[11:-33])
                    elif ("not listed" in line):
                        rawUUIDs.append(line[11:-23])
                    elif ("listed, listening" in line):
                        rawUUIDs.append(line[11:-19])
                f.write(line)
            f.close()
            g.close()

            with open(ifmap_tmp,'r') as f:
                ifmap_results_array = f.read().splitlines()

            os.remove(ifmap_tmp)
            try:
                print("Starting opdump")
                doOpdump(rawUUIDs,ifmap_results_array)
            except:
                print("Opdump failed!")
        except:
            print("Something went wrong with ifmap on %s:%s, run manually" % (ip_address, port))
    else:
        print("Unable to find ifmap, run must manually")

#Process the listening results from ifmap and get more information with opdump
def doOpdump(rawUUIDs,ifmap_results_array):
    access_denied=[]
    success=[]
    try:
        DEVNULL = open(os.devnull, 'w')
        timeout_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_opdump_timeout.txt" % (ip_address, port)
        t = open(timeout_outfile,'w')
        for UUID in rawUUIDs:
            scanme=UUID.split(" v")
            try:
                results = subprocess.check_output(['opdump.py',ip_address,port,scanme[0],scanme[1]],encoding='utf8',stderr=DEVNULL)
            except subprocess.CalledProcessError:
                t.write("opdumping UUID: " + scanme[0] + " v" + scanme[1] + " resulted in a timeout.\n")
                continue
            except Exception as e:
                print(type(e))
                print("AHHHHHH uncaught exception in ifmap: doOpdump")
                print("opdumping UUID: " + scanme[0] + " v" + scanme[1] + " resulted in a timeout.")
                continue
            if ("rpc_s_access_denied" in results):
                access_denied.append(scanme[0] + " " + scanme[1])
                access_denied.append(results)
            else:
                success.append(scanme[0] + " " + scanme[1])
                success.append(results)
        DEVNULL.close()
        denied_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_opdump_denied.txt" % (ip_address, port)
        f = open(denied_outfile, "w")
        for denied in access_denied:
            f.write(denied)
            f.write("\n")
        f.close()
        analyzeOpdump(success,ifmap_results_array)
    except NameError:
        print("Unable to run opdump without ifmap")

def analyzeOpdump(successArray,ifmap_results):
    print("Analzing opdump")
    #For success with opdump, reference the UID with limited additional information (offline)
    success_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_opdump_success.txt" % (ip_address, port)
    f = open(success_outfile, "w")
    if successArray is not None:
        for good in successArray:
            tmp_uuid=good[:-4]
            if ":" not in good:
                for ifmap in ifmap_results:
                    if str(tmp_uuid) in ifmap:
                        tmp_uuid_index = ifmap_results.index(ifmap)
                        tmp_protocol_index = tmp_uuid_index - 2
                        uuid=ifmap_results[tmp_uuid_index]
                        if ("other version listed" in uuid):
                            f.write(uuid[11:-33])
                        elif ("not listed" in uuid):
                            f.write(uuid[11:-23])
                        elif ("listed, listening" in uuid):
                            f.write(uuid[11:-19])
                        f.write(" | ")
                        f.write(ifmap_results[tmp_protocol_index])
                        f.write(good)
                        f.write("\n")
                        break
            else:
                f.write(good)
                f.write("\n")
        f.close()
    else:
        print("Unable to run opdump on successful pipes")

def doRPCDump():
    if os.path.isfile('/usr/bin/impacket-rpcdump'):
        print("Starting rpcdump")
        #more information for kicks and giggles, no auth, but it supports Hash for SMB
        rpcdump_outfile = "/root/scripts/recon_enum/results/exam/msrpc/%s_%s_rpcdump.txt" % (ip_address, port)
        results = subprocess.check_output(['impacket-rpcdump',ip_address,'-port',port],encoding='utf8')
        f = open(rpcdump_outfile, "w")
        for res in results:
            f.write(res)
        f.close()

        print("This RPCDump is NOT authenticated, you must run manually for auth")
    else:
        print("Unable to find impacket-rpcdump, you must run manually")

# mkdir_p function updated for >= python 3.5
def mkdir_p(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True) 

if __name__=='__main__':
    parser = argparse.ArgumentParser(description='Rough script to handle checking MSRPC endpoints and available pipes. Usage: msrpcrecon.py <ip address> <port>')
    parser.add_argument('ip_address', help="Ip address of target windows machine")
    parser.add_argument('port', help="Specific port to enumerate")
    args = parser.parse_args()

    ip_address = args.ip_address
    port = args.port

    BASE = "/root/scripts/recon_enum/results/exam/msrpc"
    mkdir_p(BASE)

    print("\nINFO: Starting MSRPCrecon")
    patch_ifmap()
    doNmap()
    doIFMap() #IFMap will call doOpdump and doOpdump will call analyzeOpdump
    doRPCDump()
    print("\nINFO: MSRPCrecon Complete")
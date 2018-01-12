#!/usr/bin/python

import sys
import os
import subprocess

if len(sys.argv) != 3:
    print "Usage: dirbust.py <target url> <scan name>"
    sys.exit(0)

url = str(sys.argv[1])
name = str(sys.argv[2])
folders = ["/root/lists/Web/AllWebLists/separate", "/usr/share/dirb/wordlists/vulns"]

found = []
print "INFO: Starting dirb scan for " + url
for folder in folders:
    for filename in os.listdir(folder):

	outfile = " -o " + "/root/scripts/recon_enum/results/exam/dirb/" + name + "_dirb_" + filename
	DIRBSCAN = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
        #print "Now trying dirb list: %s" % (filename)
        try:
	    results = subprocess.check_output(DIRBSCAN, shell=True)
	    resultarr = results.split("\n")
	    for line in resultarr:
	        if "+" in line:
		    if line not in found:
		        found.append(line)
	except:
	    pass

try:
    if found[0] != "":
        print "[*] Dirb found the following items..."
        for item in found:
            print "   " + item
except:
    print "INFO: No items found during dirb scan of " + url		

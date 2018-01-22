#!/usr/bin/python

import sys
import os
import subprocess

if len(sys.argv) < 3:
    print "Usage: dirbust.py <target url> <scan name> <tool-to-use (optional)>"
    print "tool-to-use: available options are dirb and gobuster. gobuster is the default"
    print "Warning: this version still uses old logic for dirb. gobuster uses new word list"
    sys.exit(0)

url = str(sys.argv[1])
name = str(sys.argv[2])

#default to gobuster
if (len(sys.argv) <= 3):
   tool = "gobuster"
else: 
   tool = str(sys.argv[3])

if (tool == "dirb"):
    folders = ["/root/lists/Web/AllWebLists/separate", "/usr/share/dirb/wordlists/vulns"]
    found = []
    print "INFO: Starting dirb scan for %s" % (url)
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


if (tool == "gobuster"):
    print "INFO: Starting gobuster scan for %s" % (url)
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
    #gobuster documentation (not all options, just common ones)
    #-a string: Set the User-Agent string (dir mode only)
    #-e	Expanded mode, print full URLs
    #-f	Append a forward-slash to each directory request (dir mode only)
    #-l	Include the length of the body in the output (dir mode only)
    #-n	Don't print status codes
    #-p string: Proxy to use for requests [http(s)://host:port] (dir mode only)
    #-q	Don't print the banner and other noise
    #-r	Follow redirects
    #-s string: Positive status codes (dir mode only) (default "200,204,301,302,307")
    #-t int: Number of concurrent threads (default 10)
    #-u string: The target URL or Domain
    #-v	Verbose output (errors)
    #-w string: Path to the wordlist
    #-x string: File extension(s) to search for (dir mode only)
    GOBUSTERSCAN = "gobuster -a %s -e -q -u %s -w /root/lists/Web/personal_with_vulns.txt > /root/scripts/recon_enum/results/exam/dirb/gobuster%s" % (user_agent, url, name)
    results = subprocess.check_output(GOBUSTERSCAN, shell=True)
            
print "INFO: Directory brute of %s completed" % (url)

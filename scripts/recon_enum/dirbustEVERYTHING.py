#!/usr/bin/python

import sys
import os
import subprocess

def help():
    print "Usage: dirbust.py <target url:port> <scan name> <tool-to-use (optional)>"
    print "tool-to-use: available options are dirb and gobuster. gobuster is the default"
    print "Warning: this version still uses old logic for dirb. gobuster uses new word list"
    print "Warning: gobuster is not set to follow redirects!"
    sys.exit(0)

if len(sys.argv) < 3:
    help()

#url is http(s)://IP_ADDRESS
url = str(sys.argv[1])

#name being passed from reconscan is an IP_ADDRESS
name = str(sys.argv[2])

if ("http" in url):
    ip_address = url.strip("http://")
elif ("https" in url):
    ip_address = url.strip("https://")

port = url.split(":")[2]

#default to gobuster
if (len(sys.argv) <= 3):
   tool = "gobuster"
else:
   if (sys.argv[3] == "dirb" or sys.argv[3] == "gobuster"):
      tool = str(sys.argv[3]) 
   help()

def genlist(url, name):
    # -c: count for each word found
    # -d: depth to spider Default 2
    # -k: keep downloaded files
    # -a: consider metadata. files downloaded to /tmp
    # --meta_file: filename for metadata output
    # --feta-temp-dir: dir to use when downloading/parsing
    # -m: min word length
    # -n: don't output the wordlist
    # -o: default, spider only visit site specified. with -o, cewl will visit external sites
    # -u: user agent, default is 'Ruby'
    # -w: file, write output rather than STDOUT
    # --auth_type: digest or basic
    # --auth_user: username
    # --auth_pass: password
    # --proxy_host: proxy
    # --proxy_port: port
    # --proxy_username: username
    # --proxy_password: password
    # -v: verbose
    print "INFO: generating custom wordlist"
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
    #TODO: Feed in URLS from a brute scan
    CEWLSCAN = "cewl -d 5 -k -a -m 5 -u '%s' %s -w /root/scripts/recon_enum/results/exam/dirb/%s" % (user_agent, url, name)
    results = subprocess.check_output(CEWLSCAN, shell=True)

def dirb(url):
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
    folders = ["/root/lists/Web/AllWebLists/separate", "/usr/share/dirb/wordlists/vulns"]
    found = []
    print "INFO: Starting dirb scan for %s" % (url)
    for folder in folders:
        for filename in os.listdir(folder):
            outfile = " -o " + "/root/scripts/recon_enum/results/exam/dirb/" + name + "_dirb_" + filename
            DIRBSCAN = "dirb %s %s/%s %s -a -S -r" % (url, folder, filename, outfile, user_agent)
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

def gobuster(url, wordlist, name):
    print "INFO: Starting gobuster scan for %s" % (url)
    user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
    if (name == ""):
        print "NAME ERROR"
        name = "TEMP_NO_NAME_PASSED"
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
    GOBUSTERSCAN = "gobuster -a '%s' -e -q -u %s -x .php,.html -l -w %s > /root/scripts/recon_enum/results/exam/dirb/gobuster%s" % (user_agent, url, wordlist, name)
    results = subprocess.check_output(GOBUSTERSCAN, shell=True)

def sortBySize(nameAndPathOfResults):
    f = open(nameAndPathOfResults, 'r')
    sizear = set()
    for line in f:
        tmpsize = line.split('[Size: ')[1]
        tmpsize = tmpsize[:-2] #-2 for ]\n, -1 leaves the ]
        sizear.add(tmpsize)
    for size in sizear:
        GREPV = "grep -v %s %s > /root/scripts/recon_enum/results/exam/dirb/gobuster_%s_%s_size_%s_only" % (size, nameAndPathOfResults, name, port, size)
        GREPVRESULTS = subprocess.call(GREPV, shell=True)

if (tool == "dirb"):
    dirb(url)

if (tool == "gobuster"):
    default_wordlist = "/root/lists/Web/personal_with_vulns.txt"
    cewl_scanname = "%s_%s_cewl" % (name, port)
    cewl_filename = "/root/scripts/recon_enum/results/exam/dirb/%s" % (cewl_scanname)
    default_scanname = "_%s_%s_default" % (name, port)
    cewl_busted_scanname = "_%s_%s_cewld" % (name, port)
    gobuster(url, default_wordlist, default_scanname)
    genlist(url, cewl_scanname)
    gobuster(url, cewl_filename, cewl_busted_scanname)
    COMUNI = "awk \'!a[$0]++\' /root/scripts/recon_enum/results/exam/dirb/gobuster* > /root/scripts/recon_enum/results/exam/dirb/gobuster_%s_%s_combined" % (name, port)
    comuniresults = subprocess.check_output(COMUNI, shell=True)
            
print "INFO: Directory brute of %s completed" % (url)

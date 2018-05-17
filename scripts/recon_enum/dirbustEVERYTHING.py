#!/usr/bin/python

import sys
import os
import subprocess
import errno

def help():
    print "Usage: dirbust.py <http(s)://target url:port> <scan name> <tool-to-use (optional)>"
    print "tool-to-use: available options are dirb and gobuster. gobuster is the default"
    print "Warning: this version still uses old logic for dirb. gobuster uses new word list"
    print "Warning: gobuster is not set to follow redirects!"
    sys.exit(0)

if len(sys.argv) < 3:
    help()

#default to gobuster
if (len(sys.argv) <= 3):
   tool = "gobuster"
else:
   if (sys.argv[3] == "dirb" or sys.argv[3] == "gobuster"):
      tool = str(sys.argv[3]) 
   help()

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

#PRIVATE VARIABLES
#url is http(s)://IP_ADDRESS
#name being passed from reconscan is an IP_ADDRESS
#User agent for tools
#Default wordlist for tools to use
url = str(sys.argv[1])
name = str(sys.argv[2])
if (name == ""):
    print "NAME ERROR"
    name = "TEMP_NO_NAME_PASSED"
user_agent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
default_wordlist = "/root/lists/Web/personal_with_vulns.txt"
if ("http" in url):
    ip_address = url.strip("http://")
elif ("https" in url):
    ip_address = url.strip("https://")
port = url.split(":")[2]

#PRIVATE FILENAMES
BASE="/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
CEWL_OUT="%s/cewl_%s_%s" % (BASE, name, port)
CEWL_TMP="%s/cewlTMP" % (BASE)
STAT_200="%s/stat200_%s_%s" % (BASE, name, port)
GOB_DEFAULT="%s/gobuster_%s_%s_default" % (BASE, name, port)
GOB_CEWL_OUTPUT="%s/gobuster_%s_%s_cewld" % (BASE, name, port)
GOB_COMBINED="%s/gobuster_%s_%s_combined" % (BASE, name, port)
WW_URLS="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatwebURLs" % (ip_address, port)
WW_OUT="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb.xml" % (ip_address, port)

#This is needed in case of odd ports. May not be only 80/443
path = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
mkdir_p(path)

def genlist():
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
    CEWLSCAN = "cewl -d 5 -k -a -m 5 -u '%s' %s -w %s" % (user_agent, url, CEWL_OUT)
    results = subprocess.check_call(CEWLSCAN, shell=True)

#Call getStatus200
#Grab CEWL output each run and add into set for uniqueness
#Iterate through set and output words for further gobusting
def genlistLoop():
    print "INFO: generating custom wordlist"
    getStatus200()
    g = open(STAT_200, 'r')
    cewldWords = set()
    for line in g:
        line = line.split(" ")[0]
        CEWLSCAN = "cewl -d 2 -k -a -m 5 -u '%s' %s -w %s" % (user_agent, line, CEWL_TMP)
        results = subprocess.check_call(CEWLSCAN, shell=True)
        h = open(CEWL_TMP, 'r')
        for res in h:
            cewldWords.add(res)
        h.close()
    g.close()
    g = open(CEWL_OUT, 'w')
    for word in cewldWords:
        g.write(word)
    g.close()

#After the first run of Gobuster, grab the results, 
#parse status 200 into another file for CEWL
def getStatus200():
    g = open(GOB_DEFAULT, 'r')
    status200=[]
    for line in g:
        if ("(Status: 200)" in line):
            status200.append(line)
    g.close()
    g = open(STAT_200, 'w')
    for line in status200:
        g.write(line)
    g.close()

def dirb(url):
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

def gobuster(wordlist, scanname):
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
    #-P string: Password for basic auth
    #-U string: Username for basic auth
    #-fw: Force continued operation when wildcard found
    GOBUSTERSCAN = "gobuster -a '%s' -e -q -u %s -x .php,.html -l -w %s > %s" % (user_agent, url, wordlist, scanname)
    results = subprocess.check_call(GOBUSTERSCAN, shell=True)

def sortBySize(nameAndPathOfResults):
    f = open(nameAndPathOfResults, 'r')
    sizear = set()
    for line in f:
        if "Size:" in line:
            tmpsize = line.split('[Size: ')[1]
            if ("\n" in tmpsize):
                tmpsize = tmpsize[:-2] #-2 for ]\n if \n exists
            else:
                tmpsize = tmpsize[:-1] #-1 for ]
            sizear.add(tmpsize)
    for size in sizear:
        GREP = "grep %s %s > %s/gobuster_%s_%s_size_%s_only" % (size, nameAndPathOfResults, BASE, name, port, size)
        GREPRESULTS = subprocess.call(GREP, shell=True)
    f.close()

def whatWeb():
    print "INFO: whatweb started on port %s" % (port)
    #
    #-i     input file
    #-a     Aggression level from 1 (quiet) to 3 (brute)
    #-u     User agent
    #-v     Verbose
    prepWhatWebFile = 'cat %s | grep -v "(" | grep -v ")" | cut -d" " -f1 > %s' % (GOB_COMBINED, WW_URLS)
    subprocess.check_call(prepWhatWebFile, shell=True)
    WHATWEBFINGER = "whatweb -i %s -u '%s' -a 3 -v --log-xml=%s" % (WW_URLS, user_agent, WW_OUT)
    subprocess.call(WHATWEBFINGER, shell=True)

if (tool == "dirb"):
    dirb(url)

if (tool == "gobuster"):
    #Process:
    #gobuster (redirect?), status 200 to CEWL, CEWL loop 200s (unique set())
    #CEWL back to gobuster, combine and unique gobuster outputs, sort by response body size
    print "INFO: Starting gobuster scan for %s" % (url)
    gobuster(default_wordlist, GOB_DEFAULT)
    print "INFO: Finished initial gobuster scan for %s:%s" % (url, port)
    genlistLoop()
    gobuster(CEWL_OUT, GOB_CEWL_OUTPUT)
    print "INFO: Finished cewl gobuster scan for %s:%s" % (url, port)
    COMUNI = "awk \'!a[$0]++\' %s/gobuster* > %s" % (BASE, GOB_COMBINED)
    comuniresults = subprocess.check_call(COMUNI, shell=True)
    sortBySize(GOB_COMBINED)
    whatWeb()

print "INFO: Directory brute of %s completed" % (url)
print "INFO: WhatWeb identification of %s completed" % (url)

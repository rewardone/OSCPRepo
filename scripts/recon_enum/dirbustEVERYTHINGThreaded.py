#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process

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
   print "Using %s" % (tool)

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
default_wordlist = "/root/lists/Web/secProb_no_ext.txt"
#default_wordlist = "/root/lists/Web/personal_with_vulns.txt"
if ("http" in url):
    ip_address = url.strip("http://")
elif ("https" in url):
    ip_address = url.strip("https://")
port = url.split(":")[2]

#PRIVATE FILENAMES
BASE="/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
LISTS="/root/lists/Web/AllWebLists/separate"
CEWL_OUT="%s/cewl_%s_%s" % (BASE, name, port)
CEWL_TMP="%s/cewlTMP" % (BASE)
STAT_200="%s/stat200_%s_%s" % (BASE, name, port)
GOB_DEFAULT="%s/gobuster_%s_%s_default" % (BASE, name, port)
GOB_CEWL_OUTPUT="%s/gobuster_%s_%s_cewld" % (BASE, name, port)
GOB_COMBINED="%s/gobuster_%s_%s_combined" % (BASE, name, port)
DIRB_DEFAULT="%s/dirb_%s_%s_default" % (BASE, name, port)
DIRB_CEWL_OUTPUT="%s/dirb_%s_%s_cewld" % (BASE, name, port)
DIRB_COMBINED="%s/dirb_%s_%s_combined" % (BASE, name, port)
WW_URLS="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatwebURLs" % (name, port)
WW_OUT="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb.xml" % (name, port)
WW_OUT_VERBOSE="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb_verbose" % (name, port)

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
def genlistLoop(tool_default_list):
    print "INFO: generating custom wordlist"
    getStatus200(tool_default_list)
    g = open(STAT_200, 'r')
    cewldWords = set()
    dev_null = open(os.devnull, 'w')
    if (os.path.getsize(STAT_200) != 0): #shouldn't happen, but if there are no 'new' dirs, just spider main page
        for line in g:
            line = line.split(" ")[0]
            #CEWLSCAN = "cewl -d 2 -k -a -m 5 -u '%s' %s -w %s" % (user_agent, line, CEWL_TMP)
            results = subprocess.check_output(['cewl','-d 2','-k','-a','-m 5','-u %s' % user_agent,line],stderr=dev_null)
            for res in results:
                cewldWords.add(res)
            #h = open(CEWL_TMP, 'r')
            #for res in h:
            #    cewldWords.add(res)
    else:
        #CEWLSCAN = "cewl -d 5 -k -a -m 5 -u '%s' %s -w %s" % (user_agent, url, CEWL_TMP)
        results = subprocess.check_output(['cewl','-d 5','-k','-a','-m 5','-u %s' % user_agent,url],stderr=dev_null)
        for res in results:
            cewldWords.add(res)
        #results = subprocess.check_call(CEWLSCAN, shell=True)
        #h = open(CEWL_TMP, 'r')
        #for res in h:
        #    cewldWords.add(res)
    #h.close()
    dev_null.close()
    g.close()
    g = open(CEWL_OUT, 'w')
    for word in cewldWords:
        g.write(word)
    g.close()

#After the first run of Gobuster, grab the results,
#parse status 200 into another file for CEWL
def getStatus200(tool_default_list): #like GOB_DEFAULT/DIRB_DEFAULT
    g = open(tool_default_list, 'r')
    status200=[]
    for line in g:
        if ("(Status: 200)" in line) or ("(CODE:200" in line): #Status for Gob, Code for dirb
            status200.append(line)
    g.close()
    g = open(STAT_200, 'w')
    for line in status200:
        g.write(line)
    g.close()

def dirb(wordlist, scanname):
    #dirb documentation (not all options, just common ones)
    #dirb <url_base> <url_base> [<wordlist_file(s)>] [options]
    #-a string:     custom User_Agent
    #-b :           don't squash or merge sequences of /../ or /./ in the given URL
    #-f:            fine tunning of NOT_FOUND (404) detection
    #-N <nf_code>:  ifnore responses with this HTTP code
    #-o <output>:   save output to disk
    #-r:            don't search recursively
    #-R:            interactive recursion (ask for each)
    #-S:            silent mode. Don't show tested words
    #-t:            don't force an ending '/' on URLs
    #-v:            show  also not existent pages
    #-w:            don't stop on warning messages
    #-x <ext_file>: amplify search with the extensions on this file
    #-X <ext>:      Amplify search with this extensions
    #-z <milisec>:  Amplify search with this extensions
    #Dirb actually cannot handle too many wordlists passed at a time....have to loop each individually
    #Dirb can't handle very large lists, 2mb seems fine, so defaulting to new secProb_no_ext.txt list
    if (wordlist == ""):
        cwd = os.getcwd() #get it so we can pop back to it later because reasons
        os.chdir(LISTS)
        files = os.listdir(LISTS)
        f = open(scanname, 'a')
        for file in files:
            DIRBSCAN = "dirb %s %s -a '%s' -b -f -S" % (url, file, user_agent)
            results = subprocess.check_call(DIRBSCAN, shell=True)
            try:
                itter = results.split("\n")
                for line in itter:
                    if ( str("+") in results) or ( str("(!)") in results):
                        f.write(results)
            except:
                pass
        os.chdir(cwd)
        f.close()
    else:
        f = open(scanname, 'w')
        DIRBSCAN = "dirb %s %s -a '%s' -b -f -S" % (url, wordlist, user_agent)
        results = subprocess.check_call(DIRBSCAN, shell=True)
        try:
            itter = results.split("\n")
            for line in itter:
                if ("+" in results) or ("(!)" in results):
                    f.write(results)
        except:
            pass
        f.close()

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
    #prepWhatWebFile = 'cat %s | grep -v "(" | grep -v ")" | cut -d" " -f1 > %s' % (GOB_COMBINED, WW_URLS)
    #subprocess.check_call(prepWhatWebFile, shell=True)
    f = open(STAT_200)
    g = open(WW_URLS,'w')
    for line in f:
        line = line.split(" ")[0]
        if "(" in line or ")" in line:
            pass
        else:
            g.write(line)
    g.close()
    f.close()
    results = subprocess.check_output(['whatweb','-i',WW_URLS,'-u',user_agent,'-a 3','-v','--log-xml',WW_OUT])
    f = open(WW_OUT_VERBOSE,'w')
    for res in results:
        f.write(res)
    f.close()
    #WHATWEBFINGER = "whatweb -i %s -u '%s' -a 3 -v --log-xml=%s" % (WW_URLS, user_agent, WW_OUT)
    #subprocess.call(WHATWEBFINGER, shell=True)

def chunkWordlist(wordlist):
    if not os.path.exists("/root/lists/Web/secProbChunked"):
        mkdir_p("/root/lists/Web/secProbChunked")
    if os.path.exists("/root/lists/Web/secProbChunked") and len(os.listdir("/root/lists/Web/secProbChunked")) == 0:
        f = open(wordlist, 'r')
        chunkCount = 0
        chunkFileCount = 0
        chunkFile = "/root/lists/Web/secProbChunked/secProb_no_ext_chunk_%s" % (str(chunkFileCount))
        origSize = subprocess.check_output(['wc', '-l', wordlist]).split(" ")[0]
        g = open(chunkFile, 'w')
        for line in f:
            g.write(line)
            if chunkCount >= (int(origSize)/3):
                g.close()
                chunkFileCount += 1
                chunkFile = "/root/lists/Web/secProbChunked/secProb_no_ext_chunk_%s" % (str(chunkFileCount))
                chunkCount = 0
                g = open(chunkFile, 'w')
            chunkCount += 1
        f.close()
        g.close()
        print "Number of chunks: %s" % (str(chunkFileCount)) 

def comuni(tool,combined_name):
    COMUNI = "awk \'!a[$0]++\' %s/%s* > %s" % (BASE, tool, combined_name)
    comuniresults = subprocess.check_call(COMUNI, shell=True)

if (tool == "dirb"):
    print "INFO: Starting dirb scan for %s:%s" % (url, port)
    dirb(default_wordlist, DIRB_DEFAULT)
    print "INFO: Finished initial dirb scan for %s:%s" % (url, port)
    genlistLoop(DIRB_DEFAULT)
    dirb(CEWL_OUT, DIRB_CEWL_OUTPUT)
    print "INFO: Finished cewl dirb scan for %s:%s" % (url, port)
    comuni("dirb",DIRB_COMBINED)
    sortBySize(DIRB_COMBINED)

if (tool == "gobuster"):
    #Process:
    #gobuster (redirect?), status 200 to CEWL, CEWL loop 200s (unique set())
    #CEWL back to gobuster, combine and unique gobuster outputs, sort by response body size
    # print "INFO: Starting gobuster scan for %s" % (url)
    # gobuster(default_wordlist, GOB_DEFAULT)
    # print "INFO: Finished initial gobuster scan for %s:%s" % (url, port)
    # genlistLoop(GOB_DEFAULT)
    # gobuster(CEWL_OUT, GOB_CEWL_OUTPUT)
    # print "INFO: Finished cewl gobuster scan for %s:%s" % (url, port)
    # comuni("gobuster",GOB_COMBINED)
    # sortBySize(GOB_COMBINED)
    #########################################################
    print "INFO: Starting threaded gobust"
    chunkWordlist(default_wordlist)
    count = 0
    jobs = []
    for chunk in os.listdir("/root/lists/Web/secProbChunked"):
        path = "/root/lists/Web/secProbChunked/%s" % chunk ##path.abspath uses CWD so hard code path here
        if os.path.getsize(path) > 0:
            scanname = "%s_%s" % (GOB_DEFAULT, str(count))
            p = multiprocessing.Process(target=gobuster, args=(path,scanname))
            p.start()
            jobs.append(p)
            count += 1
    for p in jobs:
        p.join()
    print "Finished"
    comuni("*default",GOB_DEFAULT)
    remFiles = "rm %s_*" % (GOB_DEFAULT)
    subprocess.check_output(remFiles, shell=True) #can't pass bash wildcards to subprocess
    genlistLoop(GOB_DEFAULT)
    gobuster(CEWL_OUT, GOB_CEWL_OUTPUT)
    comuni("gobuster",GOB_COMBINED)
    sortBySize(GOB_COMBINED)
    print "INFO: Finished cewl gobuster scan for %s:%s" % (url, port)

print "INFO: Directory brute of %s completed" % (url)
whatWeb()
print "INFO: WhatWeb identification of %s completed" % (url)

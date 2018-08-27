#!/usr/bin/env python

# Goal of this script is to take a vulners url and give you the short description of the CVE
# Ideally, this will be run against the vulners nmap output, which will append the description
# to each of the findings.
# Probably a lot of unnecessary code, but got incredibly frustrated debugging due to using a bad file...
# works now. I may revisit later.

import requests
import sys
import os

if len(sys.argv) != 2:
    print "Usage: getVulnersDescriptions.py <FileOrURL>"
    sys.exit(0)


if not os.path.isfile(sys.argv[1]):
    if "http" in sys.argv[1]:
        userUrl = sys.argv[1]
        req = requests.get(userUrl)
        description = req.text.split('<meta name="description" content=')[1].split('/>')[0]
        print "Description: %s" % description
else:
    userFile = sys.argv[1]
    userUrl = open(userFile,'r')
    copyFile = open("/tmp/VulnersDescription",'w')
    for line in userUrl:
        if "vulners.com" in line:
            workingLine = ""
            workingLine = line.rstrip()
            #this will parse output from nmap scripts
            #ie: | 	CVE-2010-4344		9.3		https://vulners.com/cve/CVE-2010-4344
            actualURL = workingLine.split("\t")[5].split(" ")[0]
            actualURL = actualURL.replace("\n","")
            req = requests.get(actualURL)
            if req.status_code != 200:
                continue
            req = req.text.encode("ascii","ignore")
            description = req.split('<meta name="description" content=')[1].split('/>')[0]
            description = description.rstrip()
            replace = "%s: %s" % (actualURL,description)
            replace = replace.rstrip()
            copyFile.write(workingLine + ": " + description + "\n")
        else:
            if "Vulners - Vulnerability Data Base" in line:
                line = line.replace(':"Vulners - Vulnerability Data Base" ',"")
            if "\n" not in line:
                copyFile.write(line + "\n")
                line = ""
            else:
                copyFile.write(line)
                line = ""
    userUrl.close()
    copyFile.close()
    os.rename("/tmp/VulnersDescription",os.path.abspath(sys.argv[1]))

#!/usr/bin/env python

import sys
import os
import argparse
import requests

def grabVendors():
    try:
        r = requests.get("https://cirt.net/passwords", verify=False)
        if (r.status_code == 200):
            text = r.text
            vendortmp = text.split("vendor=")
            vendors = []
            for i in range(1,len(vendortmp),1):
                vendors.append((vendortmp[i].split(">",1)[0].split("<")[0]).encode('ascii','xmlcharrefreplace'))
            return vendors    
    except:
        raise

def scrapePasswords(vendors):
    if os.path.isfile("default_passwords.txt"):
        os.remove("default_passwords.txt")
    for vendor in vendors:
        url = "https://cirt.net/passwords?vendor=%s" % vendor
        try:
            r = requests.get(url, verify=False)
        except:
            print "Something went wrong"
        text = r.text
        useridtmp = text.split("<td align=left valign=top width=300><b>User ID</b></td><td align=left width=100%>")
        passwordtmp = text.split("<tr><td align=left valign=top width=300><b>Password</b></td><td align=left width=85%>")
        useridFinal = []
        passwordFinal = []
        for i in range(1,len(useridtmp),1):
            userid = useridtmp[i].split("<",1)[0].encode('ascii','xmlcharrefreplace')
            useridFinal.append(userid)
        for i in range(1,len(passwordtmp),1):
            password = passwordtmp[i].split("<",1)[0].encode('ascii','xmlcharrefreplace')
            passwordFinal.append(password)
        
        output = open(args.outfile, 'a+')
        for i in range(1,len(useridFinal)-1,1):    
            try:
                write = "%s:%s:%s\n" % (vendor[:-1],useridFinal[i],passwordFinal[i])
                output.write(write)
            except:
                print "Write error: useridFinal may be out of bounds at i: %d" % i
                print "Write error: passwordFinal may be out of bounds at i: %d" % i


if __name__=='__main__':
    #https://cirt.net/passwords
    #https://cirt.net/passwords?vendor=Zoom
    parser = argparse.ArgumentParser(description='Rough script to scrape default passwords listed on CIRT.net')
    parser.add_argument('-o', '--out-file', nargs='?', default='default_passwords.txt', dest="outfile", help="Name of output wordlist")
    
    args = parser.parse_args()
    vendors = grabVendors()
    scrapePasswords(vendors)

#!/usr/bin/python

import sys
import os
import subprocess
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

#NSE Documentation
#Running
#ldap-novell-getpass: Retrieve Novell Universal Password for a user (requires admin account)
#ldap-rootdse: Retrieves LDAP root DSA-specific Entry

#Not Running
#ldap-brute: Brute LDAP auth
#ldap-search: Attempts to perform an LDAP search and returns all matches (requires account)
def doNmap():
    print "INFO: Starting LDAP nmap on %s:%s" % (ip_address, port)
    subprocess.check_output(['nmap','-n','-sV','-Pn','-vv','-p',port,'--script','ldap-novell-getpass,ldap-rootdse,vulners',"-oA",outfileNmap,ip_address])
    print "INFO: LDAP nmap completed on %s:%s" % (ip_address, port)
    return

# ad-ldap-enum.py [-h] -l LDAP_SERVER -d DOMAIN [-a ALT_DOMAIN] [-e] [-n] [-u USERNAME] [-p PASSWORD] [-v]
# -v, --verbose                                     Display debugging information.
# -o FILENAME_PREPEND, --prepend FILENAME_PREPEND   Prepend a string to all output file names.
# -l LDAP_SERVER, --server LDAP_SERVER              IP address of the LDAP server.
# -d DOMAIN, --domain DOMAIN                        Authentication account's FQDN. If an alternative domain is not specified this will be also used as the Base DN for searching LDAP.
# -a ALT_DOMAIN, --alt-domain ALT_DOMAIN            Alternative FQDN to use as the Base DN for searching LDAP.
# -e, --nested                                      Expand nested groups.
# Authentication Parameters:
# -n, --null                                        Use a null binding to authenticate to LDAP.
# -s, --secure                                      Connect to LDAP over SSL
# -u USERNAME, --username USERNAME                  Authentication account's username.
# -p PASSWORD, --password PASSWORD                  Authentication account's password.
#Requires python-ldap module as well (pip install python-ldap
def doADLdapEnum():
#https://github.com/CroweCybersecurity/ad-ldap-enum
    print "INFO: Starting ADLdapEnum on %s:%s" % (ip_address, port)
    f = open(outfileADLdapEnum,'w+')
    if args.username == "" and args.password == "" and args.domain != "":
        results = subprocess.check_output(['/root/Documents/ADLdapEnum/./ad-ldap-enum','-v','-l'
        , '%s' % (ip_address),'-n']).split("\n")
        if results:
            for res in results:
                f.write(res)
                f.write("\n")
        else:
            print "INFO: ADLdapEnum completed with no results on %s:%s" % (ip_address, port)
    else:
        results = subprocess.check_output(['/root/Documents/ADLdapEnum/./ad-ldap-enum','-v','-l'
        , '%s' % (ip_address),'-d',args.domain,'-u',args.username,'-p',args.password]).split("\n")
        if results:
            for res in results:
                f.write(res)
                f.write("\n")
        else:
            print "INFO: ADLdapEnum completed with no results on %s:%s" % (ip_address, port)
    f.close()
    print "INFO: Completed ADLdapEnum on %s:%s" % (ip_address, port)
    return


# usage: ldapdomaindump.py [-h] [-u USERNAME] [-p PASSWORD] [-at {NTLM,SIMPLE}]
                         # [-o DIRECTORY] [--no-html] [--no-json] [--no-grep]
                         # [--grouped-json] [-d DELIMITER] [-r] [-n DNS_SERVER]
                         # HOSTNAME
# Required options:
# HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        # connect to (use ldaps:// to use SSL)
# Main options:
# -u USERNAME, --user USERNAME
                        # DOMAIN\username for authentication, leave empty for
                        # anonymous authentication
# -p PASSWORD, --password PASSWORD
                        # Password or LM:NTLM hash, will prompt if not specified
# -at {NTLM,SIMPLE}, --authtype {NTLM,SIMPLE}
                        # Authentication type (NTLM or SIMPLE, default: NTLM)
# -o DIRECTORY, --outdir DIRECTORY
                        # Directory in which the dump will be saved (default:
                        # current)
# --no-html             Disable HTML output
# --no-json             Disable JSON output
# --no-grep             Disable Greppable output
# --grouped-json        Also write json files for grouped files (default:
                        # disabled)
# -d DELIMITER, --delimiter DELIMITER
                        # Field delimiter for greppable output (default: tab)
# -r, --resolve         Resolve computer hostnames (might take a while and
                        # cause high traffic on large networks)
# -n DNS_SERVER, --dns-server DNS_SERVER
                        # Use custom DNS resolver instead of system DNS (try a
                        # domain controller IP)    
def doLdapDD():
#https://github.com/dirkjanm/ldapdomaindump
    print "INFO: Starting LdapDD on %s:%s" % (ip_address, port)
    if args.username == "" and args.password == "":
        subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump','ldap://%s:%s' % (ip_address, port),'-o',outfileLDD])
    else:
        subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump','-u',args.username,'-p',args.password,'ldap://%s:%s' % (ip_address, port),'-o',outfileLDD])
    print "INFO: Completed LdapDD on %s:%s" % (ip_address, port)
    return
    
         
if __name__='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle ldap enumeration. Usage: ldaprecon.py {-u username -p password -d FQDN} IP {port}')
    parser.add_argument('-u', '--username', default = "", help="Username to connect as. Anonymous if not specified")
    parser.add_argument('-p', '--password', default = "", help="Password to authentication. Anonymous if not specified")
    parser.add_argument('-d', '--domain', default = "", help="FQDN")
    parser.add_argument('ip', help="IP address of target")
    parser.add_argument('port', default='389,636', help="Port. Default is 389,636")

    args = parser.parse_args()
    
    ip_address = args.ip
    port = args.port
    
    BASE = "/root/scripts/recon_enum/results/exam/ldap"
    mkdir_p(BASE)
    outfile = "%s/%s_%s_ldaprecon.txt" % (BASE, ip_address, port)
    outfileNmap = "%s/%s_%s_ldapnmap" % (BASE, ip_address, port)
    outfileADLdapEnum = "%s/%s_%s_ADLdapEnum" % (BASE, ip_address, port)
    outfileLDD = "%s/%s_%s_ldd" % (BASE, ip_address, port)
    
    doNmap()
    if args.domain != "":
        doADLdapEnum()
    doLdapDD()
    print "INFO: ldaprecon completed on %s:%s" % (ip_address, port)
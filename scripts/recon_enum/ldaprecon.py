#!/usr/bin/python

import sys
import os
import subprocess
import argparse
import errno
import getpass

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
#Requires python-ldap module as well (pip install python-ldap)
def doADLdapEnum():
#https://github.com/CroweCybersecurity/ad-ldap-enum
    print "INFO: Starting ADLdapEnum on %s:%s" % (ip_address, port)
    if args.username == "" and args.password == "" and args.domain == "":
        try: 
            if "," in args.port:
                ports = args.port.split(",")
                for port in ports:
                    outdirADLdapEnum = "%s/%s" % (BASE, port)
                    mkdir_p(outdirADLdapEnum)
                    ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -n -v" % (outdirADLdapEnum, ip_address)
                    subprocess.call(ADLDAPENUM, shell=True)
            else:
                outdirADLdapEnum = "%s/%s" % (BASE, args.port)
                mkdir_p(outdirADLdapEnum)
                ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -n -v" %(outdirADLdapEnum, ip_address)
                subprocess.call(ADLDAPENUM, shell=True)
        except subprocess.CalledProcessError as e:
            print "ADLdapEnum errorcode: " + str(e.returncode) + "\n"
    else:
        try:
            if "," in args.port:
                ports = args.port.split(",")
                for port in ports:
                    outdirADLdapEnum = "%s/%s" % (BASE, port)
                    mkdir_p(outdirADLdapEnum)
                    if port == 636:
                        ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -d %s -u %s -p %s -s -v" % (outdirADLdapEnum, ip_address, args.domain, args.username, args.password)
                        results = subprocess.call(ADLDAPENUM, shell=True)
                        continue
                    else:
                        ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -d %s -u %s -p %s -v" % (outdirADLdapEnum, ip_address, args.domain, args.username, args.password)
                        results = subprocess.call(ADLDAPENUM, shell=True)
            else: 
                outdirADLdapEnum = "%s/%s" % (BASE, args.port)
                mkdir_p(outdirADLdapEnum)
                if args.port == 636:
                    ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -d %s -u %s -p %s -s -v" % (outdirADLdapEnum, ip_address, args.domain, args.username, args.password)
                    results = subprocess.call(ADLDAPENUM, shell=True)
                else:
                    ADLDAPENUM = "cd %s && python /root/Documents/ADLdapEnum/ad-ldap-enum.py -l %s -d %s -u %s -p %s -v" % (outdirADLdapEnum, ip_address, args.domain, args.username, args.password)
                    results = subprocess.call(ADLDAPENUM, shell=True)
        except subprocess.CalledProcessError as e:
            print "ADLdapEnum errorcode: " + str(e.returncode) + "\n"
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
    print "INFO: Starting LdapDD on %s:%s" % (ip_address, args.port)
    outfileLDD = "%s/%s_%s_ldd" % (BASE, ip_address, args.port)
    DEVNULL = open(os.devnull, 'w') #because errors can be very noisy
    if args.username == "" and args.password == "":
        if "," in args.port:
            ports = args.port.split(",")
            for port in ports:
                outfileLDD = "%s/%s_%s_ldd" % (BASE, ip_address, port)
                outfileDir = "%s/%s" % (BASE, port)
                mkdir_p(outfileDir)
                try:
                    subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump.py','ldap://%s:%s' % (ip_address, port),'-o',outfileDir], stderr=DEVNULL)
                except subprocess.CalledProcessError as e:
                    f = open(outfileLDD, 'w')
                    f.write("Error code: " + str(e.returncode) + "\n")
                    f.write("Tool output: " + e.output)
                    f.close()
        else:
            try:
                outfileDir = "%s/%s" % (BASE, args.port)
                mkdir_p(outfileDir)
                subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump.py','ldap://%s:%s' % (ip_address, args.port),'-o',outfileDir], stderr=DEVNULL)
            except subprocess.CalledProcessError as e:
                f = open(outfileLDD, 'w')
                f.write("Error code: " + str(e.returncode) + "\n")
                f.write("Tool output: " + e.output)
                f.close()
    else:
        if "," in args.port:
            ports = args.port.split(",")
            for port in ports:
                outfileLDD = "%s/%s_%s_ldd" % (BASE, ip_address, port)
                outfileDir = "%s/%s" % (BASE, port)
                mkdir_p(outfileDir)
                try:
                    subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump.py','-u',args.username,'-p',args.password,'ldap://%s:%s' % (ip_address, port),'-o',outfileDir], stderr=DEVNULL)
                except subprocess.CalledProcessError as e:
                    f = open(outfileLDD, 'w')
                    f.write("Error code: " + str(e.returncode) + "\n")
                    f.write("Tool output: " + e.output)
                    f.close()
        else:
            try:
                outfileDir = "%s/%s" % (BASE, args.port)
                mkdir_p(outfileDir)
                subprocess.check_output(['/root/Documents/LdapDD/./ldapdomaindump.py','-u',args.username,'-p',args.password,'ldap://%s:%s' % (ip_address, args.port),'-o',outfileDir], stderr=DEVNULL)
            except subprocess.CalledProcessError as e:
                f = open(outfileLDD, 'w')
                f.write("Error code: " + str(e.returncode) + "\n")
                f.write("Tool output: " + e.output)
                f.close()
    print "INFO: Completed LdapDD on %s:%s" % (ip_address, args.port)
    DEVNULL.close()
    return

#tons of options, limited set here
#-b         base dn
#-c         continuous, do not stop on errors
#-f         read operations from file
#-T         write files to directory specified by path
#-D         bind DN
#-h         LDAP server
#-n         show what would be done, but don't actually do it
#-p         port
#-Q         SASL quiet mode
#-v         verbose
#-w         password for simple authentication
#-W         prompt for password
#-x         simple authentication
#-X         SASLS authorization identity
#-y         read pass from file
def doLdapSearch():
    #Bare minimum enum command is: ldapsearch -h host -p 389 -x -b "dc=mywebsite,dc=com"
    #grab the basedn from nmap (hopefully)
    print "INFO: Starting ldapsearch on %s:%s" % (ip_address, args.port)
    GREP_COMMAND = "grep namingContexts %s.nmap  | cut -d' ' -f9" % (outfileNmap)
    try:
        basedn = subprocess.check_output(GREP_COMMAND, shell=True)
        if "\n" in basedn:
            basedn = basedn[:-1]
    except subprocess.CalledProcessError as e:
        print "ldapsearch errorcode: " + str(e.returncode) + "\n"
    if "," in args.port:
        ports = args.port.split(",")
        for port in ports:
            try:
                results = subprocess.check_output(['ldapsearch','-h',ip_address,'-p',port,'-x','-b',basedn])
            except subprocess.CalledProcessError as e:
                print "ldapsearch errorcode: " + str(e.returncode) + "\n"
    else:
        try:
            results = subprocess.check_output(['ldapsearch','-h',ip_address,'-p',args.port,'-x','-b',basedn])
        except subprocess.CalledProcessError as e:
            print "ldapsearch errorcode: " + str(e.returncode) + "\n"
    f = open(outfileLdapSearch, 'w+')
    for res in results:    
        f.write(res)
    f.close()
    print "INFO: Completed ldapsearch on %s:%s" % (ip_address, args.port)
    
def cleanHistory():
    print "Cleaning history"
    bash_history = "/root/.bash_history"
    zsh_history = "/root/.zsh_history"
    if os.path.isfile(bash_history):
        os.remove(bash_history)
    if os.path.isfile(zsh_history):
        os.remove(zsh_history)


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Rough script to handle ldap enumeration. Usage: ldaprecon.py {-u username -p password -d FQDN} IP {port}')
    parser.add_argument('-u', '--username', default = "", help="Username to connect as. Anonymous if not specified. Must use Domain\\\\Username")
    parser.add_argument('-p', '--password', nargs='?', default = "", help="Password to authentication. Anonymous if not specified. Will prompt if -p. Caution as subprocess may leave passwords in history file")
    parser.add_argument('-d', '--domain', default = "", help="FQDN")
    parser.add_argument('ip', help="IP address of target")
    parser.add_argument('--port', default='389,636', dest='port', help="Port. Default is 389,636")
    parser.add_argument('--not-safe', dest='not_safe', default=False, action='store_const', const=True, help="Disable removing of bash/zsh history files. If a password is used, it will be visible in your history file. By default, ldaprecon will remove history. This flag will preserve your history file, but leave passwords in clear text")

    args = parser.parse_args()

    ip_address = args.ip
    port = args.port

    if args.username != "":
        args.password = getpass.getpass('Password: ')

    BASE = "/root/scripts/recon_enum/results/exam/ldap"
    mkdir_p(BASE)
    outfile = "%s/%s_%s_ldaprecon.txt" % (BASE, ip_address, port)
    outfileNmap = "%s/%s_%s_ldapnmap" % (BASE, ip_address, port)
    outfileLdapSearch = "%s/%s_%s_ldapsearch" % (BASE, ip_address, port)

    doNmap()
    if args.domain != "":
        doADLdapEnum()
    doLdapDD()
    doLdapSearch()
    if not args.not_safe:
        cleanHistory()
    print "INFO: ldaprecon completed on %s:%s" % (ip_address, port)
    print "Also remember PowerView and other more powerfull tools can be used with authentication"

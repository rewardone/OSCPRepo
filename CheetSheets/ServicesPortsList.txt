r                        0/tcp  # Reserved<BR>
r                        0/udp  # Reserved<BR>
tcpmux                   1/tcp  # TCP Port Service Multiplexer    One of original portmappers. SGI/IRIX is still using it, thus scans for it are probable attempts to locate IRIX targets. A &quot;HELP&quot; request to it returns Irix host's service listings.    
tcpmux                   1/udp  # TCP Port Service Multiplexer    One of original portmappers. SGI/IRIX is still using it, thus scans for it are probable attempts to locate IRIX targets. A &quot;HELP&quot; request to it returns Irix host's service listings.    
compressnet              2/tcp  # Management Utility<BR>
compressnet              2/udp  # Management Utility<BR>
compressnet              3/tcp  # Compression Process<BR>
compressnet              3/udp  # Compression Process<BR>
rje                      5/tcp  # Remote Job Entry<BR>
rje                      5/udp  # Remote Job Entry<BR>
echo                     7/tcp  # Echo<BR><br> Used to trouble-shoot remote TCP/IP stacks (telnet to remote echo port, then type ... all keystrokes will echo back if target stack is working thru app layer. <BR> <br> DOS Threat: Attackers use it to relay flooding data. If relayed to a network broadcast, entire subnet can flood. To a syslog-loghost, logs can flood. Returns it to whatever you forged as your source socket. Any data sent can flood, but looping data output ports (eg: chargen, time, daytime) create deadly streaming floods. <BR> <br> Disable on all hosts; enable only for brief trouble-shooting. <BR> 
echo                     7/udp  # Echo<BR><br> Used to trouble-shoot remote TCP/IP stacks (telnet to remote echo port, then type ... all keystrokes will echo back if target stack is working thru app layer. <BR> <br> DOS Threat: Attackers use it to relay flooding data. If relayed to a network broadcast, entire subnet can flood. To a syslog-loghost, logs can flood. Returns it to whatever you forged as your source socket. Any data sent can flood, but looping data output ports (eg: chargen, time, daytime) create deadly streaming floods. <BR> <br> Disable on all hosts; enable only for brief trouble-shooting. <BR> 
discard                  9/tcp  # Discard<BR><br> Port equiv to /dev/null. Reads pkts, then discards them. Allows knowledge the host is alive and processing pkts. Used while trouble-shooting local stack's transmit ability (telnet to discard on remote host, knowing all transmitted keystrokes will just be discarded ... no worry of corrupting host processes). <BR> <br> No threat, but block on hosts and perimeter network devices as general rule. <BR> 
discard                  9/udp  # Discard<BR><br> Port equiv to /dev/null. Reads pkts, then discards them. Allows knowledge the host is alive and processing pkts. Used while trouble-shooting local stack's transmit ability (telnet to discard on remote host, knowing all transmitted keystrokes will just be discarded ... no worry of corrupting host processes). <BR> <br> No threat, but block on hosts and perimeter network devices as general rule. <BR> 
systat                   11/tcp  # Active Users<BR><br> Provides very useful info to attackers (host's usernames, login times, origination hosts, etc.). <BR> <br> Disable this port on all hosts. <BR> 
systat                   11/udp  # Active Users<BR><br> Provides very useful info to attackers (host's usernames, login times, origination hosts, etc.). <BR> <br> Disable this port on all hosts. <BR> 
daytime                  13/tcp  # Daytime<BR><br> Returns the time of day in machine language; can return OS version. Provides host time, which can be useful in timing attacks. Also creates a DOS threat when its output is looped echo port (7). <BR> <br> Disable this port on all hosts. <BR> 
daytime                  13/udp  # Daytime<BR><br> Returns the time of day in machine language; can return OS version. Provides host time, which can be useful in timing attacks. Also creates a DOS threat when its output is looped echo port (7). <BR> <br> Disable this port on all hosts. <BR> 
netstat                  15/tcp  # Now Unassigned (was netstat)<BR><br> Netstat was similar to systat and is still active on some operating systems. Provides remote attackers info about the host and network (socket status, route tables, arp table, multicast group members, per- protocol stat's, interfaces status, etc.). <BR> <br> Disable this port on all hosts. <BR> 
netstat                  15/udp  # Now Unassigned (was netstat)<BR><br> Netstat was similar to systat and is still active on some operating systems. Provides remote attackers info about the host and network (socket status, route tables, arp table, multicast group members, per- protocol stat's, interfaces status, etc.). <BR> <br> Disable this port on all hosts. <BR> 
qotd                     17/tcp  # Quote of the Day (QOTD)<BR><br> Used to receive remote QOTDs. Used for social engineering attacks, where users receive fake instructions to verify passwords , etc. <BR> <br> Disable this port on all hosts. <BR> 
qotd                     17/udp  # Quote of the Day (QOTD)<BR><br> Used to receive remote QOTDs. Used for social engineering attacks, where users receive fake instructions to verify passwords , etc. <BR> <br> Disable this port on all hosts. <BR> 
msp                      18/tcp  # Message Send Protocol<BR>
msp                      18/udp  # Message Send Protocol<BR>
chargen                  19/tcp  # Character Generator<BR><br> Used to trouble-shoot TCP/IP stacks. Generates random characters at a high rate. <BR> <br> DOS Threat: Attackers will loop it to the echo port, creating a very effective host and subnet DOS. <BR> <br> Disable this port on all hosts, enable only for brief trouble-shooting tests.
chargen                  19/udp  # Character Generator<BR><br> Used to trouble-shoot TCP/IP stacks. Generates random characters at a high rate. <BR> <br> DOS Threat: Attackers will loop it to the echo port, creating a very effective host and subnet DOS. <BR> <br> Disable this port on all hosts, enable only for brief trouble-shooting tests.
ftp-data                 20/tcp  # Default FTP Data Transfer Port<BR><br> Is FTP service's default data transfer port; required inbound if internal users are allowed access to external FTP sites, yet open port poses a threat (hole for network mapping, etc). Modern firewalls solve this by keeping it closed until a valid FTP session exists, then only opening it between those hosts. <BR> <br> Control via a stateful-tracking firewall, do not simply open at perimeter. <BR> 
ftp-data                 20/udp  # Default FTP Data Transfer Port<BR><br> Is FTP service's default data transfer port; required inbound if internal users are allowed access to external FTP sites, yet open port poses a threat (hole for network mapping, etc). Modern firewalls solve this by keeping it closed until a valid FTP session exists, then only opening it between those hosts. <BR> <br> Control via a stateful-tracking firewall, do not simply open at perimeter. <BR> 
ftp-control              21/tcp  # FTP Control Port<BR><br> Is FTP service control port. Firewall rules focus on this port, then open port 20 only when required for a data transfer. <BR> Security Concerns with FTP: <BR> - Cleartext, re-usable passwords <BR> - Portal for user account grinding <BR> - FTP Bounce, where attacker uses ftp's "port" command to redirect the FTP transfer to a port &amp; IP other than default port 20 on the FTP server. Attacks can include "bouncing" internal network scans, email forging/flooding, etc. <BR> <br> CERT Advisories: CA-97.16, CA-99.13 <BR> <br> Disable port on non-FTP servers. <BR> <br> Open at perimeter only with static route to internal FTP server(s). <BR> 
ftp-control/ftp          21/udp  # FTP Control Port<BR><br> Is FTP service control port. Firewall rules focus on this port, then open port 20 only when required for a data transfer. <BR> Security Concerns with FTP: <BR> - Cleartext, re-usable passwords <BR> - Portal for user account grinding <BR> - FTP Bounce, where attacker uses ftp's "port" command to redirect the FTP transfer to a port &amp; IP other than default port 20 on the FTP server. Attacks can include "bouncing" internal network scans, email forging/flooding, etc. <BR> <br> CERT Advisories: CA-97.16, CA-99.13 <BR> <br> Disable port on non-FTP servers. <BR> <br> Open at perimeter only with static route to internal FTP server(s). <BR> , ftp<br><br>file transfer [control]<br>
ssh                      22/tcp  # SSH Remote Login Protocol<BR>
ssh/pcanywherestat       22/udp  # SSH Remote Login Protocol<BR>, pcAnywhere Status<BR><br> Default udp status port for v2.0 thru v7.51, plus CE. Versions v8+ on use tcp 5631 &amp; udp 5632. <BR> 
telnet                   23/tcp  # Telnet<BR><br> Standard for remote host admin. <BR> Security Concerns of Telnet: <BR> - Cleartext, re-usable passwords <BR> - Portal for user account grinding <BR> <br> CERT Advisories: CA-89.03, CA-95.14 <BR> <br> Replace with SSH on critical hosts. <BR> 
telnet                   23/udp  # Telnet<BR><br> Standard for remote host admin. <BR> Security Concerns of Telnet: <BR> - Cleartext, re-usable passwords <BR> - Portal for user account grinding <BR> <br> CERT Advisories: CA-89.03, CA-95.14 <BR> <br> Replace with SSH on critical hosts. <BR> 
smtp/smtp                25/tcp  # Simple Mail Transfer<BR><br> Used by mail servers to receive inbound email. <BR> Security Concerns: Email servers are complex engines, often run as root, and required open at most network perimeters. Thus are popular for attackers and new DOS or intrusion hacks always being found. <BR> <br> Disable on non-mail server hosts. <BR> <br> Open at perimeter only with static route to internal mail server. <BR> , smtp<br><br>simple mail transfer<br>
smtp                     25/udp  # smtp<br><br>simple mail transfer<br>
nsw-fe                   27/tcp  # NSW User System FE<BR>
nsw-fe                   27/udp  # NSW User System FE<BR>
msg-icp                  29/tcp  # MSG ICP<BR>
msg-icp                  29/udp  # MSG ICP<BR>
msg-auth                 31/tcp  # MSG Authentication<BR>
msg-auth                 31/udp  # MSG Authentication<BR>
dsp                      33/tcp  # Display Support Protocol<BR>
dsp                      33/udp  # Display Support Protocol<BR>
printer-any/priv-print     35/tcp  # Any Private Printer Server<BR>, priv-print<br><br>any private printer server<br>
printer-any/priv-print     35/udp  # Any Private Printer Server<BR>, priv-print<br><br>any private printer server<br>
time                     37/tcp  # Time<BR><br> Provides remote timing stat's of internal processing events. <BR> Security Concerns: Gives remote attacker info on host's internal processing load. Can identify critical processing times, plus output can be looped to echo port (7) and create a DOS threat to the subnet. <BR> <br> Disable this port on all hosts. <BR> 
time                     37/udp  # Time<BR><br> Provides remote timing stat's of internal processing events. <BR> Security Concerns: Gives remote attacker info on host's internal processing load. Can identify critical processing times, plus output can be looped to echo port (7) and create a DOS threat to the subnet. <BR> <br> Disable this port on all hosts. <BR> 
rap                      38/tcp  # Route Access Protocol<BR>
rap                      38/udp  # Route Access Protocol<BR>
rlp                      39/tcp  # Resource Location Protocol<BR>
rlp/rlp                  39/udp  # Resource Location Protocol<BR>, rlp<br><br>resource location, resource location protocol<br>
graphics                 41/tcp  # Graphics<BR>
graphics                 41/udp  # Graphics<BR>
nameserver               42/tcp  # Host Name Server<BR><br> Obsolete nameserver (originally DARPA's trivial name server, replaced by DNS). Is currently used by Microsoft hosts for WINS server for NetBIOS name resolves. May also be still found on some older Unix systems. <BR> <br> Disable on all non-MS-WINS hosts. <BR> 
nameserver/name          42/udp  # Host Name Server<BR><br> Obsolete nameserver (originally DARPA's trivial name server, replaced by DNS). Is currently used by Microsoft hosts for WINS server for NetBIOS name resolves. May also be still found on some older Unix systems. <BR> <br> Disable on all non-MS-WINS hosts. <BR> , name<br><br>host name server<br>
nicname                  43/tcp  # Whois<BR><br> Is the whois service, used to provide domain-level info. Sites today rarely run whois servers, is mostly just used now by Internic. Somewhat similar in function to "finger" and can suffer from same data-driven attacks. <BR> <br> Disable this port on all hosts. <BR> 
nicname/nicname          43/udp  # Whois<BR><br> Is the whois service, used to provide domain-level info. Sites today rarely run whois servers, is mostly just used now by Internic. Somewhat similar in function to "finger" and can suffer from same data-driven attacks. <BR> <br> Disable this port on all hosts. <BR> , nicname<br><br>who is, nicname<br>
mpm-flags                44/tcp  # MPM FLAGS Protocol<BR>
mpm-flags                44/udp  # MPM FLAGS Protocol<BR>
mpm                      45/tcp  # Message Processing Module [recv]<BR>
mpm                      45/udp  # Message Processing Module [recv]<BR>
mpm-snd                  46/tcp  # MPM [default send]<BR>
mpm-snd                  46/udp  # MPM [default send]<BR>
ni-ftp                   47/tcp  # NI FTP<BR>
ni-ftp                   47/udp  # NI FTP<BR>
auditd                   48/tcp  # Digital Audit Daemon<BR>
auditd                   48/udp  # Digital Audit Daemon<BR>
tacacs                   49/tcp  # Login Host Protocol (TACACS)<BR><br> Auth protocol for older terminal server logins. <BR> Security Concerns: Passwords are transmitted in cleartext <BR> <br> Previously known as bbn-login. <BR> <br> Disable this port on all hosts. <BR> 
tacacs                   49/udp  # Login Host Protocol (TACACS)<BR><br> Auth protocol for older terminal server logins. <BR> Security Concerns: Passwords are transmitted in cleartext <BR> <br> Previously known as bbn-login. <BR> <br> Disable this port on all hosts. <BR> 
re-mail-ck               50/tcp  # Remote Mail Checking Protocol<BR>
re-mail-ck               50/udp  # Remote Mail Checking Protocol<BR>
la-maint                 51/tcp  # IMP Logical Address Maintenance<BR>
la-maint                 51/udp  # IMP Logical Address Maintenance<BR>
xns-time                 52/tcp  # XNS Time Protocol<BR>
xns-time                 52/udp  # XNS Time Protocol<BR>
domain                   53/tcp  # Domain Name Server (DNS)<BR><br> DNS servers offer different services on TCP and UDP. TCP is used for "zone transfers" of full name record databases, while UDP is used for individual lookups. <BR> Security Concerns: <BR> - Zone Transfers give away entire network maps; high value to attackers <BR> - DNS (BIND) is a popular target, since DNS servers must exist, must be reachable, and exploits usually result DOS or root <BR> <br> Keep BIND version/patches current (refer to www.isca.org). <BR> <br> Use "split-DNS
domain/domain            53/udp  # Domain Name Server (DNS)<BR><br> DNS servers offer different services on TCP and UDP. TCP is used for "zone transfers" of full name record databases, while UDP is used for individual lookups. <BR> Security Concerns: <BR> - Zone Transfers give away entire network maps; high value to attackers <BR> - DNS (BIND) is a popular target, since DNS servers must exist, must be reachable, and exploits usually result DOS or root <BR> <br> Keep BIND version/patches current (refer to www.isca.org). <BR> <br> Use "split-DNS, domain<br><br>domain name server<br>
xns-ch                   54/tcp  # XNS Clearinghouse<BR>
xns-ch                   54/udp  # XNS Clearinghouse<BR>
isi-gl                   55/tcp  # ISI Graphics Language<BR>
isi-gl                   55/udp  # ISI Graphics Language<BR>
xns-auth                 56/tcp  # XNS Authentication<BR>
xns-auth                 56/udp  # XNS Authentication<BR>
terminal-any             57/tcp  # Any Private Terminal Access<BR>
terminal-any/priv-term     57/udp  # Any Private Terminal Access<BR>, priv-term<br><br>any private terminal access<br>
xns-mail                 58/tcp  # XNS Mail<BR>
xns-mail                 58/udp  # XNS Mail<BR>
dialout-any/priv-file     59/tcp  # Any Private File Service<BR>, priv-file<br><br>any private file service<br>
dialout-any/priv-file     59/udp  # Any Private File Service<BR>, priv-file<br><br>any private file service<br>
ni-mail                  61/tcp  # NI MAIL<BR>
ni-mail                  61/udp  # NI MAIL<BR>
acas                     62/tcp  # ACA Services<BR>
acas                     62/udp  # ACA Services<BR>
whois++                  63/tcp  # whois++<BR>
whois++                  63/udp  # whois++<BR>
covia                    64/tcp  # Communications Integrator (CI)<BR>
covia                    64/udp  # Communications Integrator (CI)<BR>
tacacs-ds                65/tcp  # TACACS-Database Service<BR>
tacacs-ds                65/udp  # TACACS-Database Service<BR>
sql--net/sql*net         66/tcp  # Oracle SQL<br>NET<BR><br> Used for Oracle DB access. <BR> Security Concerns: Auth scheme can be either Oracle or Unix username &amp; password combo, but both passed cleartext by default. <BR> <br> Oracle's security options: <BR> - Can encrypt the re-usable password <BR> - Can upgrade to one-time-passwords <BR> - Can enable VPN for remote access <BR> <br> Block this port at network's perimeter; use only VPN-encrypted data transfers across perimeter. <BR> , sql*net<br><br>oracle sql*net<br>
sql*net                  66/udp  # sql*net<br><br>oracle sql*net<br>
bootps                   67/tcp  # Bootstrap Protocol Server<BR><br> Listening port on bootp &amp; DHCP servers. Clients broadcast to it for boot or network parameters. <BR> Security Concern: Can probe NIS domain name, plus a valued DOS target. <BR> 
bootps/bootps            67/udp  # Bootstrap Protocol Server<BR><br> Listening port on bootp &amp; DHCP servers. Clients broadcast to it for boot or network parameters. <BR> Security Concern: Can probe NIS domain name, plus a valued DOS target. <BR> , bootps<br><br>bootp/dhcp server, bootstrap protocol server<br>
bootpc                   68/tcp  # Bootstrap Protocol Client<BR><br> Listening port on bootp &amp; DHCP clients. Servers respond to it with boot or network parameters. <BR> 
bootpc/bootpc            68/udp  # Bootstrap Protocol Client<BR><br> Listening port on bootp &amp; DHCP clients. Servers respond to it with boot or network parameters. <BR> , bootpc<br><br>bootp/dhcp client, bootstrap protocol client<br>
tftp                     69/tcp  # Trivial File Transfer<BR><br> Non-auth ftp service, used primarily by diskless clients to pull boot files. <BR> Security Concerns: Remote attackers can download server files without auth. Can extend to sensitive files (eg: passwd file) if server is poorly configured. Since file transfer is cleartext, all boot info passed to clients is vulnerable. For routers, this can include passwords. <BR> <br> Disable on host unless TFTP server. <BR> 
tftp/tftp                69/udp  # Trivial File Transfer<BR><br> Non-auth ftp service, used primarily by diskless clients to pull boot files. <BR> Security Concerns: Remote attackers can download server files without auth. Can extend to sensitive files (eg: passwd file) if server is poorly configured. Since file transfer is cleartext, all boot info passed to clients is vulnerable. For routers, this can include passwords. <BR> <br> Disable on host unless TFTP server. <BR> , tftp<br><br>trivial file transfer, trivial file transfer protocol<br>
gopher                   70/tcp  # <br> Older search engine server. Used little today, but still installed with MS's IIS.<BR><br> Disable on host unless TFTP server. <BR> 
gopher                   70/udp  # <br> Older search engine server. Used little today, but still installed with MS's IIS.<BR><br> Disable on host unless TFTP server. <BR> 
netrjs-1                 71/tcp  # Remote Job Service<BR>
netrjs-1                 71/udp  # Remote Job Service<BR>
netrjs-2                 72/tcp  # Remote Job Service<BR>
netrjs-2                 72/udp  # Remote Job Service<BR>
netrjs-3                 73/tcp  # Remote Job Service<BR>
netrjs-3                 73/udp  # Remote Job Service<BR>
netrjs-4                 74/tcp  # Remote Job Service<BR>
netrjs-4                 74/udp  # Remote Job Service<BR>
deos                     76/tcp  # Distributed External Object Store<BR>
deos                     76/udp  # Distributed External Object Store<BR>
rje-service-any          77/tcp  # Any Private RJE Service<BR>
rje-service-any/priv-rje     77/udp  # Any Private RJE Service<BR>, priv-rje<br><br>any private rje service, netjrs<br>
vettcp                   78/tcp  # vettcp<BR>
vettcp                   78/udp  # vettcp<BR>
finger                   79/tcp  # Finger<BR><br> <BR> Security Concerns: <BR> - Provides key host info to attacker <BR> - Fingered host can be DOS'd if hit with a recursive finger script till its memory and swap space fill. <BR> - Fingering clients can be DOS'd if they finger a maliciously configured host (returns data overload, causing client to beep continually, etc.). <BR> - If fingering clients allow programmable keys, a maliciously configured host can return a finger response that maps a key to "rm -rf /<br>". <BR> <br> Disable on all host unless finger service is stubbed to only provide scripted data response (eg: system admin contact info, etc.). <BR> 
finger                   79/udp  # Finger<BR><br> <BR> Security Concerns: <BR> - Provides key host info to attacker <BR> - Fingered host can be DOS'd if hit with a recursive finger script till its memory and swap space fill. <BR> - Fingering clients can be DOS'd if they finger a maliciously configured host (returns data overload, causing client to beep continually, etc.). <BR> - If fingering clients allow programmable keys, a maliciously configured host can return a finger response that maps a key to "rm -rf /<br>". <BR> <br> Disable on all host unless finger service is stubbed to only provide scripted data response (eg: system admin contact info, etc.). <BR> 
http                     80/tcp  # 'HTTP    Standard web server port.   '
http                     80/udp  # http<br><br>hypertext transfer protocol, world wide web http<br>
SIPS                     5061/tcp  # SIP over TLS/SSL
                         /udp  # 
hosts2-ns                81/tcp  # HOSTS2 Name Server<BR>
hosts2-ns                81/udp  # HOSTS2 Name Server<BR>
xfer                     82/tcp  # XFER Utility<BR>
xfer                     82/udp  # XFER Utility<BR>
mit-ml-dev               83/tcp  # MIT ML Device<BR>
mit-ml-dev               83/udp  # MIT ML Device<BR>
ctf                      84/tcp  # Common Trace Facility<BR>
ctf                      84/udp  # Common Trace Facility<BR>
mit-ml-dev               85/tcp  # MIT ML Device<BR>
mit-ml-dev               85/udp  # MIT ML Device<BR>
mfcobol                  86/tcp  # Micro Focus Cobol<BR>
mfcobol                  86/udp  # Micro Focus Cobol<BR>
link/link                87/tcp  # Any Private Terminal Link<BR><br> Popular attack target. Consider any connection attempts to it as an attack signature. <BR> , link<br><br>any private terminal link, ttylink<br>
link                     87/udp  # Any Private Terminal Link<BR><br> Popular attack target. Consider any connection attempts to it as an attack signature. <BR> 
kerberos                 88/tcp  # Kerberos<BR>
kerberos/kerberos        88/udp  # Kerberos<BR>, kerberos<br><br>kerberos (v5), krb5	<br>
su-mit-tg                89/tcp  # SU/MIT Telnet Gateway<BR>
su-mit-tg                89/udp  # SU/MIT Telnet Gateway<BR>
dnsix/pointcast          90/tcp  # DNSIX Securit Attribute Token Map<BR>, PointCast<BR>
dnsix/pointcast          90/udp  # DNSIX Securit Attribute Token Map<BR>, PointCast<BR>
mit-dov                  91/tcp  # MIT Dover Spooler<BR>
mit-dov                  91/udp  # MIT Dover Spooler<BR>
npp                      92/tcp  # Network Printing Protocol<BR>
npp                      92/udp  # Network Printing Protocol<BR>
dcp                      93/tcp  # Device Control Protocol<BR>
dcp                      93/udp  # Device Control Protocol<BR>
objcall                  94/tcp  # Tivoli Object Dispatcher<BR>
objcall                  94/udp  # Tivoli Object Dispatcher<BR>
supdup                   95/tcp  # SUPDUP<BR><br> Somewhat similar to telnet, designed for remote job entry. Is rarely used anymore, but remains a popular intruder target. Consider any connection attempts to it as an attack signature. <BR> 
supdup/supdup            95/udp  # SUPDUP<BR><br> Somewhat similar to telnet, designed for remote job entry. Is rarely used anymore, but remains a popular intruder target. Consider any connection attempts to it as an attack signature. <BR> , supdup<br><br>supdup<br>
dixie                    96/tcp  # DIXIE Protocol Specification<BR>
dixie                    96/udp  # DIXIE Protocol Specification<BR>
swift-rvf                97/tcp  # Swift Remote Virtural File Protocol<BR>
swift-rvf                97/udp  # Swift Remote Virtural File Protocol<BR>
tacnews/linux-conf       98/tcp  # TAC News<BR>, Linux Console Manager<BR>
tacnews/tacnews          98/udp  # TAC News<BR>, tacnews<br><br>tac news<br>
metagram                 99/tcp  # Metagram Relay<BR>
metagram                 99/udp  # Metagram Relay<BR>
newacct                  100/tcp  # 
                         /udp  # 
hostname                 101/tcp  # NIC Host Name Server<BR>
hostname/hostname        101/udp  # NIC Host Name Server<BR>, hostname<br><br>nic host name server, hostnames nic host name server<br>
iso-tsap/X.500           102/tcp  # ISO-TSAP Class 0<BR>, X.500 Directory Service<BR><br> Used to distribute user names, user info, and public keys. <BR> Security Concerns: Depending on vendor implementation, probes can reveal valuable user info for follow-on attacks. On poorly configured servers, attackers can replace public keys for data capture or DOS purpose. <BR> 
iso-tsap/iso-tsap        102/udp  # ISO-TSAP Class 0<BR>, iso-tsap<br><br>tsap iso-tsap class 0, iso-tsap class 0<br>
X.400/gppitnp            103/tcp  # X.400 Mail Messaging<BR><br> Both ports are used with X.400 Email std., but not widely used. No known vul's, but would similar to data-driven attacks common to smtp, plus poss. direct attacks such as with sendmail. <BR> <br> Always static route inbound mail to a protected, hardened email server. <BR> , Genesis Point-to-Point Trans Net<BR>
gppitnp/gppitnp          103/udp  # Genesis Point-to-Point Trans Net<BR>, gppitnp<br><br>genesis point-to-point trans net<br>
acr-nema                 104/tcp  # ACR-NEMA Digital Imag. &amp; Comm. 300<BR>
acr-nema                 104/udp  # ACR-NEMA Digital Imag. &amp; Comm. 300<BR>
csnet-ns/cso             105/tcp  # Mailbox Name Nameserver<BR>, CCSO name server protocol<BR>
csnet-ns/cso/cso         105/udp  # Mailbox Name Nameserver<BR>, CCSO name server protocol<BR>, cso<br><br>ccso name server protocol, mailbox name nameserver<br>
3com-tsmux/poppassd      106/tcp  # 3COM-TSMUX<BR>, POP poppassd
3com-tsmux               106/udp  # 3COM-TSMUX<BR>
rtelnet                  107/tcp  # Remote Telnet Service<BR>
rtelnet/rtelnet          107/udp  # Remote Telnet Service<BR>, rtelnet<br><br>remote telnet service<br>
snagas                   108/tcp  # SNA Gateway Access Server<BR>
snagas                   108/udp  # SNA Gateway Access Server<BR>
pop2                     109/tcp  # Post Office Protocol - Version 2<BR><br> Older POP email protocol. Replaced by POP3 (110). <BR> 
pop2/pop2                109/udp  # Post Office Protocol - Version 2<BR><br> Older POP email protocol. Replaced by POP3 (110). <BR> , pop2<br><br>postoffice v.2, post office protocol - version 2<br>
pop3                     110/tcp  # Post Office Protocol - Version 3<BR><br> Most widely used client email protocol. Used by mail clients to collect mail off server. <BR> Security Concerns: <BR> - Re-usable cleartext password <BR> - No auditing of connections &amp; attempts, thus subject to grinding <BR> - Some POP3 server versions have had buffer overflow problems <BR> <br> CERT Advisories: CA-97.09 <BR> 
pop3/pop3                110/udp  # Post Office Protocol - Version 3<BR><br> Most widely used client email protocol. Used by mail clients to collect mail off server. <BR> Security Concerns: <BR> - Re-usable cleartext password <BR> - No auditing of connections &amp; attempts, thus subject to grinding <BR> - Some POP3 server versions have had buffer overflow problems <BR> <br> CERT Advisories: CA-97.09 <BR> , pop3<br><br>postoffice v.3, post office protocol - version 3<br>
sunrpc                   111/tcp  # Sun's RPC Portmapper<BR><br> Used to map non-registered rpc service ports on most Unix systems (Irix uses port 1). <BR> Security Concerns: <BR> - Provides rpc port map w/o auth <BR> - Has no filtering or logging <BR> - Attacker rpcinfo probes quickly find your Unix hosts <BR> - Solaris hosts open a second port above 32770. Attackers will scan for and use it, knowing net devices won't watch &amp; log this like 111 traffic. <BR> <br> Enhance your portmapper to get ACL filtering and logging: <BR> - BSD: Install "portmap wrapper" <BR> - System V &amp; Solaris: Install Venema's "rpcbind replacement" <BR> <br> Both require libwrap.a from a compiled TCP Wrapper program. <BR> <br> Shut down portmapper on any hosts not requiring rpc's. <BR> <br> Ensure blocked at all net perimeters <BR> 
sunrpc/sunrpc            111/udp  # Sun's RPC Portmapper<BR><br> Used to map non-registered rpc service ports on most Unix systems (Irix uses port 1). <BR> Security Concerns: <BR> - Provides rpc port map w/o auth <BR> - Has no filtering or logging <BR> - Attacker rpcinfo probes quickly find your Unix hosts <BR> - Solaris hosts open a second port above 32770. Attackers will scan for and use it, knowing net devices won't watch &amp; log this like 111 traffic. <BR> <br> Enhance your portmapper to get ACL filtering and logging: <BR> - BSD: Install "portmap wrapper" <BR> - System V &amp; Solaris: Install Venema's "rpcbind replacement" <BR> <br> Both require libwrap.a from a compiled TCP Wrapper program. <BR> <br> Shut down portmapper on any hosts not requiring rpc's. <BR> <br> Ensure blocked at all net perimeters <BR> , sunrpc<br><br>portmapper, rpcbind, sun remote procedure call<br>
mcidas                   112/tcp  # McIDAS Data Transmission Protocol<BR>
mcidas                   112/udp  # McIDAS Data Transmission Protocol<BR>
ident/auth               113/tcp  # Ident<BR><br> Some versions vulnerable to root-level intrusion! Check! <BR> , Authentication Service<BR><br> Used by hosts to acquire info on users engaged in connections (eg: it sends socket info to remote hosts, who then passes back user info - generally data from the /etc/passwd file). Can be used to probe remote passwd file for usernames. <BR> <br> Allows you to see what account is running a particular service (eg: ident of a service can tell you if its run by root, etc.). <BR> 
auth/auth                113/udp  # Authentication Service<BR><br> Used by hosts to acquire info on users engaged in connections (eg: it sends socket info to remote hosts, who then passes back user info - generally data from the /etc/passwd file). Can be used to probe remote passwd file for usernames. <BR> <br> Allows you to see what account is running a particular service (eg: ident of a service can tell you if its run by root, etc.). <BR> , auth<br><br>authentication service, ident, tap, authentication service<br>
audionews                114/tcp  # Audio News Multicast<BR>
audionews                114/udp  # Audio News Multicast<BR>
sftp                     115/tcp  # Simple File Transfer Protocol<BR><br>Not<br> Secure FTP (ftps), which operates on ports 990 &amp;989. <BR> 
sftp                     115/udp  # Simple File Transfer Protocol<BR><br>Not<br> Secure FTP (ftps), which operates on ports 990 &amp;989. <BR> 
ansanotify               116/tcp  # ANSA REX Notify<BR>
ansanotify               116/udp  # ANSA REX Notify<BR>
uucp-path                117/tcp  # UUCP Path Service<BR>
uucp-path                117/udp  # UUCP Path Service<BR>
sqlserv                  118/tcp  # SQL Services<BR>
sqlserv                  118/udp  # SQL Services<BR>
nntp                     119/tcp  # Network News Transfer Protocol<BR><br> Usenet server feeds (uucp can be used for this too). <BR> <br> If used, config nntp server with ACL to control client access. <BR> <br> If config'd to allow non-admins to create new newsgroups, host is vulnerable to command meta-character attacks (eg: ";"). <BR> <br> nntp messages are simple ascii -- susceptable to capture, modification, &amp; forgery. <BR> <br> If an nntp server is not hosted at site, ensure it is blocked at firewall. If a server exists and firewall hole is required, proxy server in the DMZ and disable the automated group creation feature. Note that nntp servers can be established in a split-server mode similar to DNS. <BR> <br> For outbound nntp to external nntp servers (eg: Internet Usenet), primary threat is download and execution of malicious code. <BR> 
nntp/nntp                119/udp  # Network News Transfer Protocol<BR><br> Usenet server feeds (uucp can be used for this too). <BR> <br> If used, config nntp server with ACL to control client access. <BR> <br> If config'd to allow non-admins to create new newsgroups, host is vulnerable to command meta-character attacks (eg: ";"). <BR> <br> nntp messages are simple ascii -- susceptable to capture, modification, &amp; forgery. <BR> <br> If an nntp server is not hosted at site, ensure it is blocked at firewall. If a server exists and firewall hole is required, proxy server in the DMZ and disable the automated group creation feature. Note that nntp servers can be established in a split-server mode similar to DNS. <BR> <br> For outbound nntp to external nntp servers (eg: Internet Usenet), primary threat is download and execution of malicious code. <BR> , nntp<br><br>network news transfer protocol<br>
cfdptkt                  120/tcp  # CFDPTKT<BR>
cfdptkt                  120/udp  # CFDPTKT<BR>
erpc                     121/tcp  # Encore Expedited Remote Pro.Call<BR>
erpc                     121/udp  # Encore Expedited Remote Pro.Call<BR>
smakynet                 122/tcp  # SMAKYNET<BR>
smakynet                 122/udp  # SMAKYNET<BR>
ntp                      123/tcp  # Network Time Protocol<BR><br> Provides time synch between computers and network systems. Assists in database mgmt, auth schemes, and audit/logging accuracy. <BR> Security Concerns: It provides both info and an avenue of attack for intruders. Info gathered can include: system uptime, time since reset, time server pkt, I/O, &amp; memory statistics, and ntp peer list. Further, if a host is susceptible to time altering via ntp, an attacker can: <BR> 1) Run replay attacks, using captured OTP and Kerberos tickets before they expire. <BR> 2) Stop security-related cron jobs from running or cause them to run at incorrect times. <BR> 3) Make system and audit logs unreliable, since time is alterable. <BR> 
ntp                      123/udp  # Network Time Protocol<BR><br> Provides time synch between computers and network systems. Assists in database mgmt, auth schemes, and audit/logging accuracy. <BR> Security Concerns: It provides both info and an avenue of attack for intruders. Info gathered can include: system uptime, time since reset, time server pkt, I/O, &amp; memory statistics, and ntp peer list. Further, if a host is susceptible to time altering via ntp, an attacker can: <BR> 1) Run replay attacks, using captured OTP and Kerberos tickets before they expire. <BR> 2) Stop security-related cron jobs from running or cause them to run at incorrect times. <BR> 3) Make system and audit logs unreliable, since time is alterable. <BR> 
ansatrader               124/tcp  # ANSA REX Trader<BR>
ansatrader               124/udp  # ANSA REX Trader<BR>
locus-map                125/tcp  # Locus PC-Interface Net Map Server<BR>
locus-map                125/udp  # Locus PC-Interface Net Map Server<BR>
nxedit/unitary           126/tcp  # NXEdit<BR>, Unisys Unitary Login<BR>
nxedit/unitary           126/udp  # NXEdit<BR>, Unisys Unitary Login<BR>
locus-con                127/tcp  # Locus PC-Interface Conn Server<BR>
locus-con                127/udp  # Locus PC-Interface Conn Server<BR>
gss-xlicen               128/tcp  # GSS X License Verification<BR>
gss-xlicen               128/udp  # GSS X License Verification<BR>
pwdgen                   129/tcp  # Password Generator Protocol<BR>
pwdgen                   129/udp  # Password Generator Protocol<BR>
cisco-fna                130/tcp  # cisco FNATIVE<BR>
cisco-fna                130/udp  # cisco FNATIVE<BR>
cisco-tna                131/tcp  # cisco TNATIVE<BR>
cisco-tna                131/udp  # cisco TNATIVE<BR>
cisco-sys                132/tcp  # cisco SYSMAINT<BR>
cisco-sys                132/udp  # cisco SYSMAINT<BR>
statsrv                  133/tcp  # Statistics Service<BR>
statsrv                  133/udp  # Statistics Service<BR>
ingres-net               134/tcp  # INGRES-NET Service<BR>
ingres-net               134/udp  # INGRES-NET Service<BR>
loc-srv/epmap            135/tcp  # Location Service<BR><br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). TCP 135 is used for authentication, MS's DHCP Mgr, DNS admin, WINS Mgr, Exchange admin, MS RPCs, and most MS client/server apps. <br>Security Concerns: Key target in auth &amp; DOS attacks. Block at all perimeters; NIC-filter on public-exposed MS hosts., DCE endpoint resolution<br> Common on Unix hosts for certain x-displays, remote perfmon, etc.<BR> 
loc-srv/epmap/epmap      135/udp  # Location Service<BR><br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). TCP 135 is used for authentication, MS's DHCP Mgr, DNS admin, WINS Mgr, Exchange admin, MS RPCs, and most MS client/server apps. <br>Security Concerns: Key target in auth &amp; DOS attacks. Block at all perimeters; NIC-filter on public-exposed MS hosts., DCE endpoint resolution<br> Common on Unix hosts for certain x-displays, remote perfmon, etc.<BR> , epmap<br><br>dce endpoint resolution, location service<br>
profile                  136/tcp  # PROFILE Naming System<BR>
profile                  136/udp  # PROFILE Naming System<BR>
netbios-ns               137/tcp  # netbios-ns<br><br>netbios name service<br>
netbios-ns/netbios-ns     137/udp  # NETBIOS Name Service<BR><br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). UDP 137 is used for browsing, logon sequence, pass-thru validations, printing support, trust support, WinNT Secure Channel, and WINS registration.<br>Security Concerns: Key target in auth &amp; DOS attacks. Block at all perimeters; NIC-filter on public-exposed MS hosts., netbios-ns<br><br>netbios name service<br>
netbios-dgm              138/tcp  # NETBIOS Datagram Service<BR><br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). UDP 137 is used for browsing, directory replication, logon sequence, netlogon, pass-thru validation, printing support, trusts, and WinNT Secure Channel.<BR> Security Concerns: Key target in auth &amp; DOS attacks. Block at all perimeters; NIC-filter on public-exposed MS hosts.
netbios-dgm              138/udp  # NETBIOS Datagram Service<BR><br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). UDP 137 is used for browsing, directory replication, logon sequence, netlogon, pass-thru validation, printing support, trusts, and WinNT Secure Channel.<BR> Security Concerns: Key target in auth &amp; DOS attacks. Block at all perimeters; NIC-filter on public-exposed MS hosts.
netbios-ssn/netbios-ssn     139/tcp  # <br> A principle rqmt for NetBIOS services on MS hosts (Win9x/ME/NT/Win2000). TCP 139 is used for directory replication, event viewer, file sharing, logon sequence, pass-thru validation, performance monitoring, printing, registry editor, server manager, trusts, user manager, WinNT Diagnostics, and WinNT Secure Channel.<br>Security Concerns: Key target in auth &amp; DOS attacks, plus sniffer capture of sensitive data transfers. Block at all perimeters; NIC-filter on public-exposed MS hosts., netbios-ssn<br><br>netbios session service<br>
netbios-ssn              139/udp  # netbios-ssn<br><br>netbios session service<br>
emfis-data               140/tcp  # EMFIS Data Service<BR>
emfis-data               140/udp  # EMFIS Data Service<BR>
emfis-cntl               141/tcp  # EMFIS Control Service<BR>
emfis-cntl               141/udp  # EMFIS Control Service<BR>
bl-idm                   142/tcp  # Britton-Lee IDM<BR>
bl-idm                   142/udp  # Britton-Lee IDM<BR>
imap2                    143/tcp  # Internet Message Access Protocol v2<BR><br> Widely used client email protocol. Used by mail clients to collect mail off server. A superset of POP3, with enhancements. <BR> Security Concerns: <BR> - Re-usable cleartext password <BR> - No auditing of connections/attempts, thus subject to grinding <BR> - Some IMAP server versions have buffer overflow problems <BR> <br> CERT Advisories: CA-98.09, CA-97.09. <BR> <br> IMAP v3 uses port 220. <BR> 
imap2/imap               143/udp  # Internet Message Access Protocol v2<BR><br> Widely used client email protocol. Used by mail clients to collect mail off server. A superset of POP3, with enhancements. <BR> Security Concerns: <BR> - Re-usable cleartext password <BR> - No auditing of connections/attempts, thus subject to grinding <BR> - Some IMAP server versions have buffer overflow problems <BR> <br> CERT Advisories: CA-98.09, CA-97.09. <BR> <br> IMAP v3 uses port 220. <BR> , imap<br><br>internet message access protocol, internet message access proto, interim mail access protocol v2<br>
news/uma                 144/tcp  # NeWS<BR><br> Obsolete windowing system; has known vulnerabilities. Should be no reason to be enabled on any host or network perimeter. <BR> , Universal Management Architecture<BR>
news/uma                 144/udp  # NeWS<BR><br> Obsolete windowing system; has known vulnerabilities. Should be no reason to be enabled on any host or network perimeter. <BR> , Universal Management Architecture<BR>
uaac                     145/tcp  # UAAC Protocol<BR>
uaac                     145/udp  # UAAC Protocol<BR>
iso-tp0                  146/tcp  # ISO-IP0<BR>
iso-tp0                  146/udp  # ISO-IP0<BR>
iso-ip                   147/tcp  # ISO-IP<BR>
iso-ip                   147/udp  # ISO-IP<BR>
cronus/jargon            148/tcp  # CRONUS-SUPPORT<BR>, Jargon<BR>
cronus/jargon            148/udp  # CRONUS-SUPPORT<BR>, Jargon<BR>
aed-512                  149/tcp  # AED 512 Emulation Service<BR>
aed-512                  149/udp  # AED 512 Emulation Service<BR>
sql-net                  150/tcp  # SQL-NET<BR>
sql-net                  150/udp  # SQL-NET<BR>
hems                     151/tcp  # HEMS<BR>
hems                     151/udp  # HEMS<BR>
bftp                     152/tcp  # Background File Transfer Program<BR>
bftp/bftp                152/udp  # Background File Transfer Program<BR>, bftp<br><br>background file transfer program<br>
sgmp                     153/tcp  # SGMP<BR>
sgmp                     153/udp  # SGMP<BR>
netsc-prod               154/tcp  # NETSC<BR>
netsc-prod               154/udp  # NETSC<BR>
netsc-dev                155/tcp  # NETSC<BR>
netsc-dev                155/udp  # NETSC<BR>
sqlsrv                   156/tcp  # SQL Service<BR>
sqlsrv                   156/udp  # SQL Service<BR>
knet-cmp                 157/tcp  # KNET/VM Command/Message Protocol<BR>
knet-cmp                 157/udp  # KNET/VM Command/Message Protocol<BR>
pcmail-srv               158/tcp  # PCMail Server<BR>
pcmail-srv               158/udp  # PCMail Server<BR>
nss-routing              159/tcp  # NSS-Routing<BR>
nss-routing              159/udp  # NSS-Routing<BR>
sgmp-traps               160/tcp  # SGMP-Traps<BR>
sgmp-traps               160/udp  # SGMP-Traps<BR>
                         /tcp  # 
snmp                     161/udp  # SNMP Agent<BR><br> Used to connect with and configure or request data from a running snmp agent on a network host. <BR> Security Concerns: Many! <BR> - Default community strings: "public" <BR> - Cleartext data exchanges (inluding auth with string) <BR> - Not hard to trick agent into revealing its string &amp; manager IP <BR> - To access agent's data or reconfig it, only need string and source IP of snmp manager (then spoof manager) <BR> <br> Snmp v2 has better security, but is not incorporated into many products. <BR> <br> Snmp v3 is being fielded, thus will slowly take over. <BR> 
                         /tcp  # 
snmptrap                 162/udp  # SNMPTrap<BR><br> Used for agent alerts to snmp manager. Data is cleartext and sniffable. Manager is susceptible to forged alert floods. <BR> 
cmip-man                 163/tcp  # CMIP/TCP Manager<BR>
cmip-man/cmip-man        163/udp  # CMIP/TCP Manager<BR>, cmip-man<br><br>cmip/tcp manager<br>
cmip-agent               164/tcp  # CMIP/TCP Agent<BR>
cmip-agent/smip-agent     164/udp  # CMIP/TCP Agent<BR>, smip-agent<br><br>cmip/tcp agent<br>
xns-courier              165/tcp  # Xerox<BR>
xns-courier              165/udp  # Xerox<BR>
s-net                    166/tcp  # Sirius Systems<BR>
s-net                    166/udp  # Sirius Systems<BR>
namp                     167/tcp  # NAMP<BR>
namp                     167/udp  # NAMP<BR>
rsvd                     168/tcp  # RSVD<BR>
rsvd                     168/udp  # RSVD<BR>
send                     169/tcp  # SEND<BR>
send                     169/udp  # SEND<BR>
print-srv                170/tcp  # Network PostScript<BR>
print-srv                170/udp  # Network PostScript<BR>
multiplex                171/tcp  # Network Innovations Multiplex<BR>
multiplex                171/udp  # Network Innovations Multiplex<BR>
cl/1                     172/tcp  # Network Innovations CL/1<BR>
cl/1                     172/udp  # Network Innovations CL/1<BR>
xyplex-mux               173/tcp  # Xyplex<BR>
xyplex-mux               173/udp  # Xyplex<BR>
mailq                    174/tcp  # MAILQ<BR>
mailq/mailq              174/udp  # MAILQ<BR>, mailq<br><br>mailq<br>
vmnet                    175/tcp  # VMNET<BR>
vmnet                    175/udp  # VMNET<BR>
genrad-mux               176/tcp  # GENRAD-MUX<BR>
genrad-mux               176/udp  # GENRAD-MUX<BR>
xdmcp                    177/tcp  # X Display Manager Control (X11 Logon)<BR><br> Used by X-Display Manager for logins. Localhost's CDE needs xdmcp open, it accesses the xdmcp daemon via tcp connection call to itself. <BR> Security Concerns: Vulnerable to sniffing, spoofing, and session hijacking. If needed open to support localhost CDE, wrap it! <BR> 
xdmcp/xdmcp              177/udp  # X Display Manager Control (X11 Logon)<BR><br> Used by X-Display Manager for logins. Localhost's CDE needs xdmcp open, it accesses the xdmcp daemon via tcp connection call to itself. <BR> Security Concerns: Vulnerable to sniffing, spoofing, and session hijacking. If needed open to support localhost CDE, wrap it! <BR> , xdmcp<br><br>x display manager control protocol<br>
nextstep                 178/tcp  # NextStep Window Server<BR><br> Auth protocol used by the NEXTSTEP Windows Server, of which few remain in existence. It is unlikely to be required on the network and should be blocked. <BR> 
nextstep/nextstep        178/udp  # NextStep Window Server<BR><br> Auth protocol used by the NEXTSTEP Windows Server, of which few remain in existence. It is unlikely to be required on the network and should be blocked. <BR> , nextstep<br><br>nextstep window server, server<br>
bgp                      179/tcp  # Border Gateway Protocol<BR><br> One of the several route protocols in use. <BR> 
bgp/bgp                  179/udp  # Border Gateway Protocol<BR><br> One of the several route protocols in use. <BR> , bgp<br><br>border gateway protocol<br>
ris                      180/tcp  # Intergraph<BR>
ris                      180/udp  # Intergraph<BR>
unify                    181/tcp  # Unify<BR>
unify                    181/udp  # Unify<BR>
audit                    182/tcp  # Unisys Audit SITP<BR>
audit                    182/udp  # Unisys Audit SITP<BR>
ocbinder                 183/tcp  # OCBinder<BR>
ocbinder                 183/udp  # OCBinder<BR>
ocserver                 184/tcp  # OCServer<BR>
ocserver                 184/udp  # OCServer<BR>
remote-kis               185/tcp  # Remote-KIS<BR>
remote-kis               185/udp  # Remote-KIS<BR>
kis                      186/tcp  # KIS Protocol<BR>
kis                      186/udp  # KIS Protocol<BR>
aci                      187/tcp  # Application Communication Interface<BR>
aci                      187/udp  # Application Communication Interface<BR>
mumps                    188/tcp  # Plus Five's MUMPS<BR>
mumps                    188/udp  # Plus Five's MUMPS<BR>
qft                      189/tcp  # Queued File Transport<BR>
qft                      189/udp  # Queued File Transport<BR>
gacp                     190/tcp  # Gateway Access Control Protocol<BR>
gacp                     190/udp  # Gateway Access Control Protocol<BR>
prospero                 191/tcp  # Prospero Directory Service<BR>
prospero/prospero        191/udp  # Prospero Directory Service<BR>, prospero<br><br>prospero directory service<br>
osu-nms                  192/tcp  # OSU Network Monitoring System<BR>
osu-nms                  192/udp  # OSU Network Monitoring System<BR>
srmp                     193/tcp  # Spider Remote Monitoring Protocol<BR>
srmp                     193/udp  # Spider Remote Monitoring Protocol<BR>
irc                      194/tcp  # Internet Relay Chat Protocol<BR>
irc/irc                  194/udp  # Internet Relay Chat Protocol<BR>, irc<br><br>internet relay chat protocol<br>
dn6-nlm-aud              195/tcp  # DNSIX Network Level Module Audit<BR>
dn6-nlm-aud              195/udp  # DNSIX Network Level Module Audit<BR>
dn6-smm-red              196/tcp  # DNSIX Session Mgt Module Audit Redir<BR>
dn6-smm-red              196/udp  # DNSIX Session Mgt Module Audit Redir<BR>
dls                      197/tcp  # Directory Location Service<BR>
dls                      197/udp  # Directory Location Service<BR>
dls-mon                  198/tcp  # Directory Location Service Monitor<BR>
dls-mon                  198/udp  # Directory Location Service Monitor<BR>
smux                     199/tcp  # SMUX (SNMP Unix Multiplexer)<BR>
smux/smux                199/udp  # SMUX (SNMP Unix Multiplexer)<BR>, smux<br><br>smux<br>
src                      200/tcp  # IBM System Resource Controller<BR>
src                      200/udp  # IBM System Resource Controller<BR>
at-rtmp                  201/tcp  # AppleTalk Routing Maintenance<BR>
at-rtmp/at-rtmp          201/udp  # AppleTalk Routing Maintenance<BR>, at-rtmp<br><br>appletalk routing maintenance<br>
at-nbp                   202/tcp  # AppleTalk Name Binding<BR>
at-nbp                   202/udp  # AppleTalk Name Binding<BR>
at-3                     203/tcp  # AppleTalk Unused<BR>
at-3                     203/udp  # AppleTalk Unused<BR>
at-echo                  204/tcp  # AppleTalk Echo<BR>
at-echo                  204/udp  # AppleTalk Echo<BR>
at-5                     205/tcp  # AppleTalk Unused<BR>
at-5                     205/udp  # AppleTalk Unused<BR>
at-zis                   206/tcp  # AppleTalk Zone Info<BR>
at-zis                   206/udp  # AppleTalk Zone Info<BR>
at-7                     207/tcp  # AppleTalk Unused<BR>
at-7                     207/udp  # AppleTalk Unused<BR>
at-8                     208/tcp  # AppleTalk Unused<BR>
at-8                     208/udp  # AppleTalk Unused<BR>
qmtp                     209/tcp  # Quick Mail Transfer Protocol<BR>
qmtp                     209/udp  # Quick Mail Transfer Protocol<BR>
wais/z39.50              210/tcp  # Wide Area Info Service (WAIS)<BR><br> Old, once popular as a database indexing and search tool. Being replaced by web structures and web-based search engines. <BR> Security Concerns: <BR> - Access control was only source IP based, thus vulnerable to spoofing <BR> - Would allow unchecked files to be retrieved and run, opening dangers to malicious code being downloaded to client <BR> , ANSI Z39.50<BR>
z39.50/z39.50            210/udp  # ANSI Z39.50<BR>, z39.50<br><br>wais, ansi z39.50, ansi z39.50<br>
914c/g                   211/tcp  # Texas Instruments 914C/G-Terminal<BR>
914c/g                   211/udp  # Texas Instruments 914C/G-Terminal<BR>
anet                     212/tcp  # ATEXSSTR<BR>
anet                     212/udp  # ATEXSSTR<BR>
ipx                      213/tcp  # IPX<BR>
ipx                      213/udp  # IPX<BR>
vmpwscs                  214/tcp  # VM PWSCS<BR>
vmpwscs                  214/udp  # VM PWSCS<BR>
softpc                   215/tcp  # Insignia Solutions<BR>
softpc                   215/udp  # Insignia Solutions<BR>
CAIlic                   216/tcp  # Computer Associates Int'l License Server<BR>
CAIlic                   216/udp  # Computer Associates Int'l License Server<BR>
dbase                    217/tcp  # dBASE Unix<BR>
dbase                    217/udp  # dBASE Unix<BR>
mpp                      218/tcp  # Netix Message Posting Protocol<BR>
mpp                      218/udp  # Netix Message Posting Protocol<BR>
uarps                    219/tcp  # Unisys ARPs<BR>
uarps                    219/udp  # Unisys ARPs<BR>
imap3                    220/tcp  # Interactive Mail Access Protocol v3<BR>
imap3/imap3              220/udp  # Interactive Mail Access Protocol v3<BR>, imap3<br><br>protocol v3, interactive mail access protocol v3<br>
fln-spx                  221/tcp  # Berkeley rlogind with SPX auth<BR>
fln-spx                  221/udp  # Berkeley rlogind with SPX auth<BR>
rsh-spx                  222/tcp  # Berkeley rshd with SPX auth<BR>
rsh-spx                  222/udp  # Berkeley rshd with SPX auth<BR>
cdc                      223/tcp  # Certificate Distribution Center<BR>
cdc                      223/udp  # Certificate Distribution Center<BR>
masqdialer               224/tcp  # Masqdialer<BR>
masqdialer               224/udp  # Masqdialer<BR>
#direct/direct           242/tcp  # Now Unassigned (Was "Direct")<BR>, direct<br><br>direct<br>
#direct/direct           242/udp  # Now Unassigned (Was "Direct")<BR>, direct<br><br>direct<br>
sur-meas                 243/tcp  # Survey Measurement<BR>
sur-meas                 243/udp  # Survey Measurement<BR>
#dayna/inbusiness        244/tcp  # Now Unassigned (Was "Dayna")<BR>, InBusiness<BR>
#dayna/inbusiness        244/udp  # Now Unassigned (Was "Dayna")<BR>, InBusiness<BR>
link                     245/tcp  # LINK<BR>
link                     245/udp  # LINK<BR>
dsp3270                  246/tcp  # Display Systems Protocol<BR>
dsp3270                  246/udp  # Display Systems Protocol<BR>
subntbcst_tftp           247/tcp  # SUBNTBCST_TFTP<BR>
subntbcst_tftp           247/udp  # SUBNTBCST_TFTP<BR>
bhfhs                    248/tcp  # bhfhs<BR>
bhfhs                    248/udp  # bhfhs<BR>
fw1-mgmt/rap             256/tcp  # Firewall-1 Mgmt Console (CheckPoint)<BR><br> FW-1's Mgmt Console port. Functions include: <BR> - CA/DH key exchange for FWZ &amp; SKIP VPN crypto schemes <BR> - SecuRemote connection to pull net topology &amp; crypto keys (v40, changed to tcp 254 in v4.1). <BR> - Mgmt Console connection to managed firewalls &amp; policies <BR> - Fail-over FW-1 heartbeat cks (pkt tx every 50ms) <BR> <br> FW-1 Ports: tcp 256, tcp/udp 259, udp 500, tcp 900 <BR> , RAP<BR>
rap                      256/udp  # RAP<BR>
set                      257/tcp  # Secure Electronic Transaction<BR>
set                      257/udp  # Secure Electronic Transaction<BR>
yak-chat                 258/tcp  # Yak Winsock Personal Chat<BR>
yak-chat                 258/udp  # Yak Winsock Personal Chat<BR>
fw1-auth/esro-gen        259/tcp  # Firewall-1 Auth (CheckPoint)<BR><br> FW-1's user &amp; client auth port. Remote clients telnet to this on perimeter firewall and auth to access internal resources (encryption an option). Services via this telnet include internal FTP, HTTP/HTTPS servers, plus relay to other internal hosts via add'l telnets/rlogins. <BR> <br> FW-1 Ports: tcp 256, tcp/udp 259, udp 500, tcp 900 <BR> , Efficient Short Remote Operations<BR>
fw1-rpc/esro-gen         259/udp  # Firewall-1 RDP (CheckPoint)<BR><br> FW-1's Reliable Datagram Protocol, used by FW-1's to agree on VPN crypto parameters. RDP provides out-of-band sessions, plus: <BR> - Negotiation of session keys <BR> - Agreement on session crypto algorithm (DES or FWZ-1) <BR> - Decision on if MD5 data integrity will be used <BR> - Ensures dropped UDP pkts are retransmitted <BR> <br> FW-1 Ports: tcp 256, tcp/udp 259, udp 500, tcp 900 <BR> , Efficient Short Remote Operations<BR>
openport                 260/tcp  # Openport<BR>
openport                 260/udp  # Openport<BR>
nsiiops                  261/tcp  # IIOP Name Service over TLS/SSL<BR>
nsiiops                  261/udp  # IIOP Name Service over TLS/SSL<BR>
arcisdms                 262/tcp  # Arcisdms<BR>
arcisdms                 262/udp  # Arcisdms<BR>
hdap                     263/tcp  # HDAP<BR>
hdap                     263/udp  # HDAP<BR>
bgmp                     264/tcp  # BGMP<BR>
bgmp                     264/udp  # BGMP<BR>
x-bone-ctl               265/tcp  # X-Bone CTL<BR>
x-bone-ctl               265/udp  # X-Bone CTL<BR>
http-mgmt                280/tcp  # http-mgmt<BR>
http-mgmt                280/udp  # http-mgmt<BR>
personal-link            281/tcp  # Personal Link<BR>
personal-link            281/udp  # Personal Link<BR>
cableport-ax             282/tcp  # Cable Port A/X<BR>
cableport-ax             282/udp  # Cable Port A/X<BR>
rescap                   283/tcp  # rescap<BR>
rescap                   283/udp  # rescap<BR>
corerjd                  284/tcp  # corerjd<BR>
corerjd                  284/udp  # corerjd<BR>
novastorbakcup           308/tcp  # Novastor Backup<BR>
novastorbakcup           308/udp  # Novastor Backup<BR>
entrusttime              309/tcp  # EntrustTime<BR>
entrusttime              309/udp  # EntrustTime<BR>
bhmds                    310/tcp  # bhmds<BR>
bhmds                    310/udp  # bhmds<BR>
asip-webadmin            311/tcp  # AppleShare IP WebAdmin<BR>
asip-webadmin            311/udp  # AppleShare IP WebAdmin<BR>
vslmp                    312/tcp  # VSLMP<BR>
vslmp                    312/udp  # VSLMP<BR>
magenta-logic            313/tcp  # Magenta Logic<BR>
magenta-logic            313/udp  # Magenta Logic<BR>
opalis-robot             314/tcp  # Opalis Robot<BR>
opalis-robot             314/udp  # Opalis Robot<BR>
dpsi                     315/tcp  # DPSI<BR>
dpsi                     315/udp  # DPSI<BR>
decauth                  316/tcp  # decAuth<BR>
decauth                  316/udp  # decAuth<BR>
zannet                   317/tcp  # Zannet<BR>
zannet                   317/udp  # Zannet<BR>
pkix-timestamp           318/tcp  # PKIX TimeStamp<BR>
pkix-timestamp           318/udp  # PKIX TimeStamp<BR>
ptp-event                319/tcp  # PTP Event<BR>
ptp-event                319/udp  # PTP Event<BR>
ptp-general              320/tcp  # PTP General<BR>
ptp-general              320/udp  # PTP General<BR>
pip                      321/tcp  # PIP<BR>
pip                      321/udp  # PIP<BR>
rtsps                    322/tcp  # RTSPS<BR>
rtsps                    322/udp  # RTSPS<BR>
texar                    333/tcp  # Texar Security Port<BR>
texar                    333/udp  # Texar Security Port<BR>
pdap                     344/tcp  # Prospero Data Access Protocol<BR>
pdap                     344/udp  # Prospero Data Access Protocol<BR>
pawserv                  345/tcp  # Perf Analysis Workbench<BR>
pawserv                  345/udp  # Perf Analysis Workbench<BR>
zserv                    346/tcp  # Zebra server<BR>
zserv                    346/udp  # Zebra server<BR>
fatserv                  347/tcp  # Fatmen Server<BR>
fatserv                  347/udp  # Fatmen Server<BR>
csi-sgwp                 348/tcp  # Cabletron Management Protocol<BR>
csi-sgwp                 348/udp  # Cabletron Management Protocol<BR>
mftp                     349/tcp  # mftp<BR>
mftp                     349/udp  # mftp<BR>
matip-type-a             350/tcp  # MATIP Type A<BR>
matip-type-a             350/udp  # MATIP Type A<BR>
matip-type-b/bhoetty     351/tcp  # MATIP Type B<BR>, bhoetty<BR>
matip-type-b/bhoetty/matip-type-b     351/udp  # MATIP Type B<BR>, bhoetty<BR>, matip-type-b<br><br>unassigned but widespread use, matip type b or bhoetty, bhoetty, matip type b<br>
bhoedap4/dtag-ste-sb     352/tcp  # bhoedap4<BR>, DTAG<BR>
bhoedap4/dtag-ste-sb/dtag-ste-sb     352/udp  # bhoedap4<BR>, DTAG<BR>, dtag-ste-sb<br><br>dtag, unassigned but widespread use, dtag, or bhoedap4, bhoedap4<br>
ndsauth                  353/tcp  # NDSAUTH<BR>
ndsauth                  353/udp  # NDSAUTH<BR>
bh611                    354/tcp  # bh611<BR>
bh611                    354/udp  # bh611<BR>
date-asn/datex-asn       355/tcp  # DATEX-ASN<BR>, datex-asn<br><br>datex-asn<br>
date-asn/datex-asn       355/udp  # DATEX-ASN<BR>, datex-asn<br><br>datex-asn<br>
cloanto-net-1            356/tcp  # Cloanto Net 1<BR>
cloanto-net-1            356/udp  # Cloanto Net 1<BR>
bhevent                  357/tcp  # bhevent<BR>
bhevent                  357/udp  # bhevent<BR>
shrinkwrap               358/tcp  # Shrinkwrap<BR>
shrinkwrap               358/udp  # Shrinkwrap<BR>
tenebris_nts             359/tcp  # Tenebris Network Trace Service<BR>
tenebris_nts             359/udp  # Tenebris Network Trace Service<BR>
scoi2odialog             360/tcp  # scoi2odialog<BR>
scoi2odialog             360/udp  # scoi2odialog<BR>
semantix                 361/tcp  # Semantix<BR>
semantix                 361/udp  # Semantix<BR>
srssend                  362/tcp  # SRS Send<BR>
srssend                  362/udp  # SRS Send<BR>
rsvp_tunnel              363/tcp  # RSVP Tunnel<BR>
rsvp_tunnel              363/udp  # RSVP Tunnel<BR>
aurora-cmgr              364/tcp  # Aurora CMGR<BR>
aurora-cmgr              364/udp  # Aurora CMGR<BR>
dtk                      365/tcp  # Deception Tool Kit<BR><br> Deception Tool Kit (DTK), a honeypot kit available at http://all.net/dtk/. On this port DTK advertises itself as a honeypot. Concept is that it will be spotted in scans and attackers will realize the net has defenses and move on. To attackers "not in the know
dtk                      365/udp  # Deception Tool Kit<BR><br> Deception Tool Kit (DTK), a honeypot kit available at http://all.net/dtk/. On this port DTK advertises itself as a honeypot. Concept is that it will be spotted in scans and attackers will realize the net has defenses and move on. To attackers "not in the know
odmr                     366/tcp  # ODMR<BR>
odmr                     366/udp  # ODMR<BR>
mortgageware             367/tcp  # MortgageWare<BR>
mortgageware             367/udp  # MortgageWare<BR>
qbikgdp                  368/tcp  # QbikGDP<BR>
qbikgdp                  368/udp  # QbikGDP<BR>
rpc2portmap              369/tcp  # rpc2portmap<BR>
rpc2portmap              369/udp  # rpc2portmap<BR>
codaauth2                370/tcp  # codaauth2<BR>
codaauth2/backweb        370/udp  # codaauth2<BR>, BackWeb<BR><br> UDP service similar to PointCast's TCP service. <BR> 
clearcase                371/tcp  # Clearcase<BR>
clearcase                371/udp  # Clearcase<BR>
ulistproc                372/tcp  # Unix Listserv<BR>
ulistproc                372/udp  # Unix Listserv<BR>
legent-1                 373/tcp  # Legent Corporation<BR>
legent-1                 373/udp  # Legent Corporation<BR>
legent-2                 374/tcp  # Legent Corporation<BR>
legent-2                 374/udp  # Legent Corporation<BR>
hassle                   375/tcp  # Hassle<BR>
hassle                   375/udp  # Hassle<BR>
nip                      376/tcp  # Amiga Envoy Network Inquiry Proto<BR>
nip                      376/udp  # Amiga Envoy Network Inquiry Proto<BR>
tnETOS                   377/tcp  # NEC Corporation<BR>
tnETOS                   377/udp  # NEC Corporation<BR>
dsETOS                   378/tcp  # NEC Corporation<BR>
dsETOS                   378/udp  # NEC Corporation<BR>
is99c                    379/tcp  # TIA/EIA/IS-99 modem client<BR>
is99c                    379/udp  # TIA/EIA/IS-99 modem client<BR>
is99s                    380/tcp  # TIA/EIA/IS-99 modem server<BR>
is99s                    380/udp  # TIA/EIA/IS-99 modem server<BR>
hp-collector             381/tcp  # HP Performance Data Collector<BR>
hp-collector             381/udp  # HP Performance Data Collector<BR>
hp-managed-node          382/tcp  # HP Performance Data Managed Node<BR><br> Host port for centralized performance monitor access. <BR> 
hp-managed-node          382/udp  # HP Performance Data Managed Node<BR><br> Host port for centralized performance monitor access. <BR> 
hp-alarm-mgr             383/tcp  # HP Performance Data Alarm Manager<BR>
hp-alarm-mgr             383/udp  # HP Performance Data Alarm Manager<BR>
arns                     384/tcp  # A Remote Network Server System<BR>
arns                     384/udp  # A Remote Network Server System<BR>
ibm-app                  385/tcp  # IBM Application<BR>
ibm-app                  385/udp  # IBM Application<BR>
asa                      386/tcp  # ASA Message Router Object Def.<BR>
asa                      386/udp  # ASA Message Router Object Def.<BR>
aurp                     387/tcp  # Appletalk Update-Based Routing Pro.<BR>
aurp                     387/udp  # Appletalk Update-Based Routing Pro.<BR>
unidata-ldm              388/tcp  # Unidata LDM Version 4<BR>
unidata-ldm              388/udp  # Unidata LDM Version 4<BR>
ldap                     389/tcp  # Lightweight Directory Access Protocol<BR><br> LDAP server's port, an adaptation of x.500 dir std. Through it, LDAP clients access central dir to retrieve, add, and modify info. Examples: <BR> - Database for PKI systems <BR> - Address book for mail &amp; personnel progs <BR> - Internet Directory Service that tracks users of collaborative apps (chat, video, audio, etc.). Would track who is on-line, their IP, and data about user.<br> Used by Win2000 Active Directory<br> SSL version at TCP 636<BR> Security Concerns: Valuable source of user info used in attacks; excellent target for DOS attack. <BR> 
ldap                     389/udp  # Lightweight Directory Access Protocol<BR><br> LDAP server's port, an adaptation of x.500 dir std. Through it, LDAP clients access central dir to retrieve, add, and modify info. Examples: <BR> - Database for PKI systems <BR> - Address book for mail &amp; personnel progs <BR> - Internet Directory Service that tracks users of collaborative apps (chat, video, audio, etc.). Would track who is on-line, their IP, and data about user.<br> Used by Win2000 Active Directory<br> SSL version at TCP 636<BR> Security Concerns: Valuable source of user info used in attacks; excellent target for DOS attack. <BR> 
uis                      390/tcp  # UIS<BR>
uis                      390/udp  # UIS<BR>
synotics-relay           391/tcp  # SynOptics SNMP Relay Port<BR>
synotics-relay           391/udp  # SynOptics SNMP Relay Port<BR>
synotics-broker          392/tcp  # SynOptics Port Broker Port<BR>
synotics-broker          392/udp  # SynOptics Port Broker Port<BR>
dis                      393/tcp  # Data Interpretation System<BR>
dis                      393/udp  # Data Interpretation System<BR>
embl-ndt                 394/tcp  # EMBL Nucleic Data Transfer<BR>
embl-ndt                 394/udp  # EMBL Nucleic Data Transfer<BR>
netcp                    395/tcp  # NETscout Control Protocol<BR>
netcp                    395/udp  # NETscout Control Protocol<BR>
netware-ip               396/tcp  # Novell Netware over IP<BR>
netware-ip               396/udp  # Novell Netware over IP<BR>
mptn                     397/tcp  # Multi Protocol Trans. Net.<BR>
mptn                     397/udp  # Multi Protocol Trans. Net.<BR>
kryptolan                398/tcp  # Kryptolan<BR>
kryptolan                398/udp  # Kryptolan<BR>
iso-tsap-c2              399/tcp  # ISO Transport Class-2 Non-Ctrl over TCP<BR>
iso-tsap-c2              399/udp  # ISO Transport Class-2 Non-Ctrl over TCP<BR>
work-sol                 400/tcp  # Workstation Solutions<BR>
work-sol                 400/udp  # Workstation Solutions<BR>
ups                      401/tcp  # Uninterruptible Power Supply<BR>
ups                      401/udp  # Uninterruptible Power Supply<BR>
genie                    402/tcp  # Genie Protocol<BR>
genie                    402/udp  # Genie Protocol<BR>
decap                    403/tcp  # decap<BR>
decap                    403/udp  # decap<BR>
nced                     404/tcp  # nced<BR>
nced                     404/udp  # nced<BR>
ncld                     405/tcp  # ncld<BR>
ncld                     405/udp  # ncld<BR>
imsp                     406/tcp  # Interactive Mail Support Protocol<BR>
imsp                     406/udp  # Interactive Mail Support Protocol<BR>
timbuktu                 407/tcp  # Timbuktu<BR>
timbuktu                 407/udp  # Timbuktu<BR>
prm-sm                   408/tcp  # Prospero Resource Manager - Sys. Mgr<BR>
prm-sm                   408/udp  # Prospero Resource Manager - Sys. Mgr<BR>
prm-nm                   409/tcp  # Prospero Resource Manager - Node Mgr<BR>
prm-nm                   409/udp  # Prospero Resource Manager - Node Mgr<BR>
decladebug               410/tcp  # DECLadebug Remote Debug Protocol<BR>
decladebug               410/udp  # DECLadebug Remote Debug Protocol<BR>
rmt                      411/tcp  # Remote MT Protocol<BR>
rmt                      411/udp  # Remote MT Protocol<BR>
synoptics-trap           412/tcp  # Trap Convention Port<BR>
synoptics-trap           412/udp  # Trap Convention Port<BR>
smsp                     413/tcp  # SMSP<BR>
smsp                     413/udp  # SMSP<BR>
infoseek                 414/tcp  # InfoSeek<BR>
infoseek                 414/udp  # InfoSeek<BR>
bnet                     415/tcp  # BNet<BR>
bnet                     415/udp  # BNet<BR>
silverplatter            416/tcp  # SilverPlatter<BR>
silverplatter            416/udp  # SilverPlatter<BR>
onmux                    417/tcp  # Onmux<BR>
onmux                    417/udp  # Onmux<BR>
hyper-g                  418/tcp  # Hyper-G<BR>
hyper-g                  418/udp  # Hyper-G<BR>
ariel1                   419/tcp  # Ariel<BR>
ariel1                   419/udp  # Ariel<BR>
smpte                    420/tcp  # SMPTE<BR>
smpte                    420/udp  # SMPTE<BR>
wrapper-backdoor/ariel2     421/tcp  # Intruder Backdoor vis TCP Wrappers<BR><br> Primary web site for TCP Wrapper distro was compromised in Jan 99 and wrapper software was trojanized. Was caught almost immediately, but some downloads occurred. Installing it open a backdoor on tcp port 421. Hosts with open tcp port 421 and wrappers should be investigated. <BR> , Ariel<BR>
ariel2                   421/udp  # Ariel<BR>
ariel3                   422/tcp  # Ariel<BR>
ariel3                   422/udp  # Ariel<BR>
opc-job-start            423/tcp  # IBM Operations Planning and Control Start<BR>
opc-job-start            423/udp  # IBM Operations Planning and Control Start<BR>
opc-job-track            424/tcp  # IBM Operations Planning and Control Track<BR>
opc-job-track            424/udp  # IBM Operations Planning and Control Track<BR>
icad-el                  425/tcp  # ICAD<BR>
icad-el                  425/udp  # ICAD<BR>
smartsdp                 426/tcp  # smartsdp<BR>
smartsdp                 426/udp  # smartsdp<BR>
svrloc                   427/tcp  # Server Location<BR><br> Open on Win95 hosts (only open default port). Useful for finding Win95 hosts. No know "direct attack" vulnerabilities. <BR> 
svrloc                   427/udp  # Server Location<BR><br> Open on Win95 hosts (only open default port). Useful for finding Win95 hosts. No know "direct attack" vulnerabilities. <BR> 
ocs_cmu                  428/tcp  # OCS_CMU<BR>
ocs_cmu                  428/udp  # OCS_CMU<BR>
ocs_amu                  429/tcp  # OCS_AMU<BR>
ocs_amu                  429/udp  # OCS_AMU<BR>
utmpsd                   430/tcp  # UTMPSD<BR>
utmpsd                   430/udp  # UTMPSD<BR>
utmpcd                   431/tcp  # UTMPCD<BR>
utmpcd                   431/udp  # UTMPCD<BR>
iasd                     432/tcp  # IASD<BR>
iasd                     432/udp  # IASD<BR>
nnsp                     433/tcp  # NNSP<BR>
nnsp/nnsp                433/udp  # NNSP<BR>, nnsp<br><br>nnsp<br>
mobileip-agent           434/tcp  # MobileIP-Agent<BR>
mobileip-agent           434/udp  # MobileIP-Agent<BR>
mobilip-mn               435/tcp  # MobilIP-MN<BR>
mobilip-mn               435/udp  # MobilIP-MN<BR>
dna-cml                  436/tcp  # DNA-CML<BR>
dna-cml                  436/udp  # DNA-CML<BR>
comscm                   437/tcp  # comscm<BR>
comscm                   437/udp  # comscm<BR>
dsfgw                    438/tcp  # dsfgw<BR>
dsfgw                    438/udp  # dsfgw<BR>
dasp                     439/tcp  # dasp<BR>
dasp/dasp                439/udp  # dasp<BR>, dasp<br><br>dasp      tommy@inlab.m.eunet.de<br>
sgcp                     440/tcp  # sgcp<BR>
sgcp                     440/udp  # sgcp<BR>
decvms-sysmgt            441/tcp  # decvms-sysmgt<BR>
decvms-sysmgt            441/udp  # decvms-sysmgt<BR>
cvc_hostd                442/tcp  # cvc_hostd<BR>
cvc_hostd                442/udp  # cvc_hostd<BR>
https                    443/tcp  # HTTP over TLS/SSL  
https                    443/udp  # https<br><br>http protocol over tls/ssl<br>
snpp                     444/tcp  # Simple Network Paging Protocol<BR>
snpp                     444/udp  # Simple Network Paging Protocol<BR>
microsoft-ds             445/tcp  # Microsoft Direct Host<BR> 
microsoft-ds             445/udp  # Microsoft Direct Host<BR> 
ddm-rdb                  446/tcp  # DDM-RDB<BR>
ddm-rdb                  446/udp  # DDM-RDB<BR>
ddm-dfm                  447/tcp  # DDM-RFM<BR>
ddm-dfm                  447/udp  # DDM-RFM<BR>
ddm-ssl                  448/tcp  # DDM-SSL<BR><br> Also known as "ddm-byte" <BR> 
ddm-ssl                  448/udp  # DDM-SSL<BR><br> Also known as "ddm-byte" <BR> 
as-servermap             449/tcp  # AS Server Mapper<BR>
as-servermap             449/udp  # AS Server Mapper<BR>
tserver                  450/tcp  # TServer<BR>
tserver                  450/udp  # TServer<BR>
sfs-smp-net              451/tcp  # Cray Network Semaphore server<BR>
sfs-smp-net              451/udp  # Cray Network Semaphore server<BR>
sfs-config               452/tcp  # Cray SFS config server<BR>
sfs-config               452/udp  # Cray SFS config server<BR>
creativeserver           453/tcp  # CreativeServer<BR>
creativeserver           453/udp  # CreativeServer<BR>
contentserver            454/tcp  # ContentServer<BR>
contentserver            454/udp  # ContentServer<BR>
creativepartnr           455/tcp  # CreativePartnr<BR>
creativepartnr           455/udp  # CreativePartnr<BR>
macon-tcp                456/tcp  # macon-tcp<BR>
macon-udp                456/udp  # macon-udp<BR>
scohelp                  457/tcp  # scohelp<BR>
scohelp                  457/udp  # scohelp<BR>
appleqtc                 458/tcp  # apple quick time<BR>
appleqtc                 458/udp  # apple quick time<BR>
ampr-rcmd                459/tcp  # ampr-rcmd<BR>
ampr-rcmd                459/udp  # ampr-rcmd<BR>
skronk                   460/tcp  # skronk<BR>
skronk                   460/udp  # skronk<BR>
datasurfsrv              461/tcp  # DataRampSrv<BR>
datasurfsrv              461/udp  # DataRampSrv<BR>
datasurfsrvsec           462/tcp  # DataRampSrvSec<BR>
datasurfsrvsec           462/udp  # DataRampSrvSec<BR>
alpes                    463/tcp  # alpes<BR>
alpes                    463/udp  # alpes<BR>
kpasswd                  464/tcp  # kpasswd<BR>
kpasswd                  464/udp  # kpasswd<BR>
smtps                    465/tcp  # SMTP over TLS/SSL (was ssmtp)<BR>
smtps                    465/udp  # SMTP over TLS/SSL (was ssmtp)<BR>
digital-vrc              466/tcp  # digital-vrc<BR>
digital-vrc              466/udp  # digital-vrc<BR>
mylex-mapd               467/tcp  # mylex-mapd<BR>
mylex-mapd               467/udp  # mylex-mapd<BR>
photuris                 468/tcp  # proturis<BR>
photuris/photuris        468/udp  # proturis<BR>, photuris<br><br>proturis<br>
rcp                      469/tcp  # Radio Control Protocol<BR>
rcp                      469/udp  # Radio Control Protocol<BR>
scx-proxy                470/tcp  # scx-proxy<BR>
scx-proxy                470/udp  # scx-proxy<BR>
mondex                   471/tcp  # Mondex<BR>
mondex                   471/udp  # Mondex<BR>
ljk-login                472/tcp  # ljk-login<BR>
ljk-login                472/udp  # ljk-login<BR>
hybrid-pop               473/tcp  # hybrid-pop<BR>
hybrid-pop               473/udp  # hybrid-pop<BR>
tn-tl-w1                 474/tcp  # tn-tl-w1<BR>
tn-tl-w1/tn-tl-w2        474/udp  # tn-tl-w1<BR>, tn-tl-w2<br><br>tn-tl-w2<br>
tcpnethaspsrv            475/tcp  # tcpnethaspsrv<BR>
tcpnethaspsrv            475/udp  # tcpnethaspsrv<BR>
tn-tl-fd1                476/tcp  # tn-tl-fd1<BR>
tn-tl-fd1                476/udp  # tn-tl-fd1<BR>
ss7ns                    477/tcp  # ss7ns<BR>
ss7ns                    477/udp  # ss7ns<BR>
spsc                     478/tcp  # spsc<BR>
spsc                     478/udp  # spsc<BR>
iafserver                479/tcp  # iafserver<BR>
iafserver                479/udp  # iafserver<BR>
iafdbase                 480/tcp  # iafdbase<BR>
iafdbase                 480/udp  # iafdbase<BR>
ph                       481/tcp  # Ph service<BR>
ph                       481/udp  # Ph service<BR>
bgs-nsi                  482/tcp  # bgs-nsi<BR>
bgs-nsi                  482/udp  # bgs-nsi<BR>
ulpnet                   483/tcp  # ulpnet<BR>
ulpnet                   483/udp  # ulpnet<BR>
integra-sme              484/tcp  # Integra Software Mgmt Environment<BR>
integra-sme              484/udp  # Integra Software Mgmt Environment<BR>
powerburst               485/tcp  # Air Soft Power Burst<BR>
powerburst               485/udp  # Air Soft Power Burst<BR>
avian                    486/tcp  # avian<BR>
avian                    486/udp  # avian<BR>
saft                     487/tcp  # saft<BR>
saft                     487/udp  # saft<BR>
gss-http                 488/tcp  # gss-http<BR>
gss-http                 488/udp  # gss-http<BR>
nest-protocol            489/tcp  # nest-protocol<BR>
nest-protocol            489/udp  # nest-protocol<BR>
micom-pfs                490/tcp  # micom-pfs<BR>
micom-pfs                490/udp  # micom-pfs<BR>
go-login                 491/tcp  # go-login<BR>
go-login                 491/udp  # go-login<BR>
ticf-1                   492/tcp  # Transport Independent Convergence, FNA<BR>
ticf-1                   492/udp  # Transport Independent Convergence, FNA<BR>
ticf-2                   493/tcp  # Transport Independent Convergence, FNA<BR>
ticf-2                   493/udp  # Transport Independent Convergence, FNA<BR>
pov-ray                  494/tcp  # POV-Ray<BR>
pov-ray                  494/udp  # POV-Ray<BR>
intecourier              495/tcp  # intecourier<BR>
intecourier              495/udp  # intecourier<BR>
pim-rp-disc              496/tcp  # PIM-RP-DISC<BR>
pim-rp-disc              496/udp  # PIM-RP-DISC<BR>
dantz                    497/tcp  # dantz<BR>
dantz                    497/udp  # dantz<BR>
siam                     498/tcp  # siam<BR>
siam                     498/udp  # siam<BR>
iso-ill                  499/tcp  # ISO ILL Protocol<BR>
iso-ill                  499/udp  # ISO ILL Protocol<BR>
                         /tcp  # 
isakmp                   500/udp  # isakmp<BR><br> Used in FW-1 VPN for key exchange &amp; synch when using ISAKMP or IPSEC crypto between FW-1's. <BR> <br> FW-1 Ports: tcp 256, tcp/udp 259, udp 500, tcp 900 <BR> 
stmf                     501/tcp  # STMF<BR>
stmf                     501/udp  # STMF<BR>
asa-appl-proto           502/tcp  # ASA Application Protocol<BR>
asa-appl-proto           502/udp  # ASA Application Protocol<BR>
intrinsa                 503/tcp  # Intrinsa<BR>
intrinsa                 503/udp  # Intrinsa<BR>
citadel                  504/tcp  # citadel<BR>
citadel                  504/udp  # citadel<BR>
mailbox-lm               505/tcp  # Mailbox License Manager<BR>
mailbox-lm               505/udp  # Mailbox License Manager<BR>
ohimsrv                  506/tcp  # ohimsrv<BR>
ohimsrv                  506/udp  # ohimsrv<BR>
crs                      507/tcp  # crs<BR>
crs                      507/udp  # crs<BR>
xvttp                    508/tcp  # xvttp<BR>
xvttp                    508/udp  # xvttp<BR>
snare                    509/tcp  # snare<BR>
snare                    509/udp  # snare<BR>
fcp                      510/tcp  # FirstClass Protocol<BR>
fcp                      510/udp  # FirstClass Protocol<BR>
mynet/passgo             511/tcp  # mynet-as<BR>, PassGo<BR>
mynet/passgo             511/udp  # mynet-as<BR>, PassGo<BR>
nt-printer-client/exec     512/tcp  # NT v4 Printer Client Source Ports<BR><br> NT v4 client uses random source port in 512-1023 range. Older NT v3x was limited to 721-731 port range, which restricted to ten the number of consecutive print jobs a client could initiate. <BR> , Remote Execution<BR><br> Allows remote execution of commands without logon. <BR> Security Concerns: <BR> - Susceptable to trust attacks <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Returns "Login incorrect" on incorrect usernames; allows username guessing. <BR> - Returns "Password incorrect" on incorrect password for valid username; allows scripted dictionary grinding. <BR> <br> As with all BSD "r" commands, client uses a random source port below 1023; causes rule headaches. <BR> 
biff/comsat              512/udp  # Mail System Notify<BR><br> Email arrival notifier. Susceptable to notification flooding, where remote attacker causes DOS of user screen by flooding it with mail notices. <BR> 512 udp ComSat <BR> ComSat <BR> , comsat<br><br>biff the dog, used by mail system to notify users, comsat<br>
login                    513/tcp  # Remote Login<BR><br> Remote term service that operates via telnet process, but with automatic auth performed based on trust. If no trust, will prompt for username/password logon similar to telnet. <BR> Security Concerns: <BR> - Susceptable to trust attacks <BR> - Usernames &amp; passwords are cleartext and reusable <BR> <br> As with all BSD "r" commands, client uses a random source port below 1023; causes rule headaches. <BR> <br> CERT Advisories: CA-97.06 <BR> 
who                      513/udp  # Remote Logon Database Lookup<BR><br> Gathers active user info from local and net hosts. <BR> Security Concerns: <BR> - Excellent source of user info <BR> - Guides user-session attacks <BR> - Vul to being fed malicious data and crashing <BR> - Vul to buffer overflow allowing remote execution of arbitrary commands with root privilege <BR> 
shell                    514/tcp  # Remote Shell<BR><br> Provides shell connections from remote hosts. <BR> Security Concerns: <BR> - Susceptable to trust attacks <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Returns "Login incorrect" on incorrect usernames; allows username guessing. <BR> - Returns "Password incorrect" on incorrect password for valid username; allows scripted dictionary grinding. <BR> <br> As with all BSD "r" commands, client uses a random source port below 1023; causes rule headaches. <BR> 
syslog                   514/udp  # Remote Syslog Writes<BR><br> Accepts syslog entries from remote hosts. Localhost syslog daemon processes and logs them, thus allowing for centralization of system logs onto a hardened loghost. <BR> Security Concerns: <BR> - Vul to malicious log flooding <BR> - Vul to injection of false, misleading entries to cover other activity <BR> <br> Newer Linux &amp; Solaris v2.6+ will not accept syslog entries by default. Requires syslog.conf edit to enable. <BR> <br> CERT Advisories: CA-95.13 <BR> 
printer                  515/tcp  # lp &amp; lpr spooler<BR><br> Service port accepting remote print jobs. <BR> Security Concerns: <BR> - Susceptable to trust attacks <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Vul to assortment of printer service attacks (version dependent) <BR> <br> As with all BSD "r" commands, client uses a random source port below 1023; causes rule headaches. <BR> 
printer/printer          515/udp  # lp &amp; lpr spooler<BR><br> Service port accepting remote print jobs. <BR> Security Concerns: <BR> - Susceptable to trust attacks <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Vul to assortment of printer service attacks (version dependent) <BR> <br> As with all BSD "r" commands, client uses a random source port below 1023; causes rule headaches. <BR> , printer<br><br>spooler, spooler (lpd)<br>
videotex                 516/tcp  # videotex<BR>
videotex                 516/udp  # videotex<BR>
                         /tcp  # 
talk                     517/udp  # Like tenex link, but remote<BR><br> Older talk program. Uses udp 517 to establish session and negotiate random-high tcp port for the data tx. <BR> Security Concerns: <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Vul to buffer overflow <BR> <br> CERT Advisories: CA-97.04 <BR> 
ntalk                    518/tcp  # ntalk<br><br>(talkd)<br>
ntalk/ntalk              518/udp  # New Talk<BR><br> Similar to talk, but more advanced in memory use and ability to work between CPU types. Like talk, it uses udp port to establish session and negotiate a random-high tcp port for the data tx. <BR> Security Concerns: <BR> - Usernames &amp; passwords are cleartext and reusable <BR> - Vul to buffer overflow <BR> , ntalk<br><br>(talkd)<br>
utime                    519/tcp  # unixtime<BR>
utime                    519/udp  # unixtime<BR>
efs                      520/tcp  # Extended file name server<BR>
router                   520/udp  # Route Info Protocol (RIP)<BR><br> Used between routing hosts to advertise route table. <BR> Security Concerns: <BR> - Vul to malicious route updates, which provides several attack possibilities: <BR> -- DOS network w/ bad updates <BR> -- Route traffic to you for exploit <BR> -- Route your attack pkts around network defenses <BR> 
ripng                    521/tcp  # ripng<BR>
ripng/ripng              521/udp  # ripng<BR>, ripng<br><br>ripng<br>
ulp                      522/tcp  # User Locator Service<BR><br> Used by collaborative apps to track/locate active users (eg: NetMeeting). <BR> Security Concerns: Provides valuable user info for user-level attacks. Do not allow across untrusted nets without encryption. <BR> 
ulp                      522/udp  # User Locator Service<BR><br> Used by collaborative apps to track/locate active users (eg: NetMeeting). <BR> Security Concerns: Provides valuable user info for user-level attacks. Do not allow across untrusted nets without encryption. <BR> 
ibm-db2                  523/tcp  # IBM-DB2<BR>
ibm-db2                  523/udp  # IBM-DB2<BR>
ncp                      524/tcp  # NCP<BR>
ncp                      524/udp  # NCP<BR>
timed                    525/tcp  # Time Server<BR>
timed                    525/udp  # Time Server<BR>
tempo                    526/tcp  # NewDate<BR>
tempo                    526/udp  # NewDate<BR>
stx                      527/tcp  # Stock IXChange<BR>
stx                      527/udp  # Stock IXChange<BR>
custix                   528/tcp  # Customer IXChange<BR>
custix                   528/udp  # Customer IXChange<BR>
irc-serv                 529/tcp  # IRC-SERV<BR>
irc-serv                 529/udp  # IRC-SERV<BR>
courier                  530/tcp  # rpc<BR>
courier/courier          530/udp  # rpc<BR>, courier<br><br>rpc<br>
conference               531/tcp  # Chat<BR>
conference               531/udp  # Chat<BR>
netnews                  532/tcp  # ReadNews<BR>
netnews                  532/udp  # ReadNews<BR>
netwall                  533/tcp  # For emergency broadcasts<BR>
netwall/netwall          533/udp  # For emergency broadcasts<BR>, netwall<br><br>-for emergency broadcasts, for emergency broadcasts<br>
mm-admin                 534/tcp  # MegaMedia Admin<BR>
mm-admin                 534/udp  # MegaMedia Admin<BR>
iiop                     535/tcp  # iiop<BR>
iiop                     535/udp  # iiop<BR>
opalis-rdv               536/tcp  # opalis-rdv<BR>
opalis-rdv               536/udp  # opalis-rdv<BR>
nmsp                     537/tcp  # Networked Media Streaming Protocol<BR>
nmsp                     537/udp  # Networked Media Streaming Protocol<BR>
gdomap                   538/tcp  # gdomap<BR>
gdomap                   538/udp  # gdomap<BR>
apertus-ldp              539/tcp  # Apertus Tech Load Determination<BR>
apertus-ldp              539/udp  # Apertus Tech Load Determination<BR>
uucp                     540/tcp  # Unix to Unix Copy<BR><br> Original Unix copy service, becoming obsolete. Is still used to some remote sites where periodic connection &amp; download of spooled data files is the normal comm. <BR> Security Concern: Usernames &amp; passwords are cleartext and reusable. <BR> 
uucp/uucp                540/udp  # Unix to Unix Copy<BR><br> Original Unix copy service, becoming obsolete. Is still used to some remote sites where periodic connection &amp; download of spooled data files is the normal comm. <BR> Security Concern: Usernames &amp; passwords are cleartext and reusable. <BR> , uucp<br><br>uucpd<br>
uucp-rlogin              541/tcp  # uucp-rlogin<BR>
uucp-rlogin/uucp-rlogin     541/udp  # uucp-rlogin<BR>, uucp-rlogin<br><br>uucp-rlogin<br>
commerce                 542/tcp  # commerce<BR>
commerce                 542/udp  # commerce<BR>
klogin                   543/tcp  # klogin<BR>
klogin/klogin            543/udp  # klogin<BR>, klogin<br><br>kerberos (v4/v5)<br>
kshell                   544/tcp  # krcmd<BR>
kshell/kshell            544/udp  # krcmd<BR>, kshell<br><br>krcmd, kerberos (v4/v5), krcmd kerberos (v4/v5)<br>
appleqtcsrvr             545/tcp  # appleqtcsrvr<BR>
appleqtcsrvr/appleqtcsrvr     545/udp  # appleqtcsrvr<BR>, appleqtcsrvr<br><br>appleqtcsrvr<br>
dhcpv6-client            546/tcp  # DHCPv6 Client<BR>
dhcpv6-client            546/udp  # DHCPv6 Client<BR>
dhcpv6-server            547/tcp  # DHCPv6 Server<BR>
dhcpv6-server            547/udp  # DHCPv6 Server<BR>
afpovertcp               548/tcp  # AFP over TCP<BR>
afpovertcp/afpovertcp     548/udp  # AFP over TCP<BR>, afpovertcp<br><br>appleshareip protocol, afp over tcp, afp over udp<br>
idfp                     549/tcp  # IDFP<BR>
idfp                     549/udp  # IDFP<BR>
new-rwho                 550/tcp  # new-who<BR>
new-rwho/new-rwho        550/udp  # new-who<BR>, new-rwho<br><br>new-who, experimental<br>
cybercash                551/tcp  # cybercash<BR>
cybercash                551/udp  # cybercash<BR>
deviceshare              552/tcp  # deviceshare<BR>
deviceshare              552/udp  # deviceshare<BR>
pirp                     553/tcp  # pirp<BR>
pirp                     553/udp  # pirp<BR>
rtsp                     554/tcp  # Real Time Stream Control Protocol<BR>
rtsp                     554/udp  # Real Time Stream Control Protocol<BR>
dsf                      555/tcp  # dsf<BR>
dsf                      555/udp  # dsf<BR>
remotefs                 556/tcp  # rfs server<BR>
remotefs                 556/udp  # rfs server<BR>
openvms-sysipc           557/tcp  # openvms-sysipc<BR>
openvms-sysipc           557/udp  # openvms-sysipc<BR>
sdnskmp                  558/tcp  # SDNSKMP<BR>
sdnskmp                  558/udp  # SDNSKMP<BR>
teedtap                  559/tcp  # TEEDTAP<BR>
teedtap                  559/udp  # TEEDTAP<BR>
rmonitor                 560/tcp  # rmonitord<BR>
rmonitor/rmonitor        560/udp  # rmonitord<BR>, rmonitor<br><br>experimental, rmonitord<br>
monitor                  561/tcp  # monitor<BR>
monitor/monitor          561/udp  # monitor<BR>, monitor<br><br>experimental<br>
chshell                  562/tcp  # chcmd<BR>
chshell                  562/udp  # chcmd<BR>
nntps                    563/tcp  # NNTP over TLS/SSL<BR><br> Was formerly snntp, snews <BR> 
nntps                    563/udp  # NNTP over TLS/SSL<BR><br> Was formerly snntp, snews <BR> 
9pfs                     564/tcp  # Plan 9 file service<BR>
9pfs                     564/udp  # Plan 9 file service<BR>
whoami                   565/tcp  # whoami<BR>
whoami                   565/udp  # whoami<BR>
streettalk               566/tcp  # streettalk<BR>
streettalk               566/udp  # streettalk<BR>
banyan-rpc               567/tcp  # banyan-rpc<BR>
banyan-rpc               567/udp  # banyan-rpc<BR>
ms-shuttle               568/tcp  # microsoft shuttle<BR>
ms-shuttle               568/udp  # microsoft shuttle<BR>
ms-rome                  569/tcp  # microsoft rome<BR>
ms-rome                  569/udp  # microsoft rome<BR>
meter                    570/tcp  # demon<BR>
meter                    570/udp  # demon<BR>
meter                    571/tcp  # udemon<BR>
meter                    571/udp  # udemon<BR>
sonar                    572/tcp  # sonar<BR>
sonar                    572/udp  # sonar<BR>
banyan-vip               573/tcp  # banyan-vip<BR>
banyan-vip               573/udp  # banyan-vip<BR>
ftp-agent                574/tcp  # FTP Software Agent System<BR>
ftp-agent                574/udp  # FTP Software Agent System<BR>
vemmi                    575/tcp  # VEMMI<BR>
vemmi                    575/udp  # VEMMI<BR>
ipcd                     576/tcp  # ipcd<BR>
ipcd                     576/udp  # ipcd<BR>
vnas                     577/tcp  # vnas<BR>
vnas                     577/udp  # vnas<BR>
ipdd                     578/tcp  # ipdd<BR>
ipdd                     578/udp  # ipdd<BR>
decbsrv                  579/tcp  # decbsrv<BR>
decbsrv                  579/udp  # decbsrv<BR>
sntp-heartbeat           580/tcp  # SNTP HEARTBEAT<BR>
sntp-heartbeat           580/udp  # SNTP HEARTBEAT<BR>
bdp                      581/tcp  # Bundle Discovery Protocol<BR>
bdp                      581/udp  # Bundle Discovery Protocol<BR>
scc-security             582/tcp  # SCC Security<BR>
scc-security             582/udp  # SCC Security<BR>
philips-vc               583/tcp  # Philips Video-Conferencing<BR>
philips-vc               583/udp  # Philips Video-Conferencing<BR>
keyserver                584/tcp  # Key Server<BR>
keyserver                584/udp  # Key Server<BR>
imap4-ssl                585/tcp  # IMAP4+SSL<BR>
imap4-ssl/imap4-ssl      585/udp  # IMAP4+SSL<BR>, imap4-ssl<br><br>use 993 instead), imap4+ssl (use 993 instead)<br>
password-chg             586/tcp  # Password Change<BR>
password-chg             586/udp  # Password Change<BR>
submission               587/tcp  # Submission<BR>
submission               587/udp  # Submission<BR>
cal                      588/tcp  # CAL<BR>
cal                      588/udp  # CAL<BR>
eyelink                  589/tcp  # EyeLink<BR>
eyelink                  589/udp  # EyeLink<BR>
tns-cml                  590/tcp  # TNS CML<BR>
tns-cml                  590/udp  # TNS CML<BR>
http-alt                 591/tcp  # FileMaker, Inc. - HTTP Alternative<BR>
http-alt                 591/udp  # FileMaker, Inc. - HTTP Alternative<BR>
eudora-set               592/tcp  # Eudora Set<BR>
eudora-set               592/udp  # Eudora Set<BR>
http-rpc-epmap           593/tcp  # HTTP RPC Ep Map<BR><br> Enabled on NT servers running SNA RPC. <BR> 
http-rpc-epmap           593/udp  # HTTP RPC Ep Map<BR><br> Enabled on NT servers running SNA RPC. <BR> 
tpip                     594/tcp  # TPIP<BR>
tpip                     594/udp  # TPIP<BR>
cab-protocol             595/tcp  # CAB Protocol<BR>
cab-protocol             595/udp  # CAB Protocol<BR>
smsd                     596/tcp  # SMSD<BR>
smsd                     596/udp  # SMSD<BR>
ptcnameservice           597/tcp  # PTC Name Service<BR>
ptcnameservice           597/udp  # PTC Name Service<BR>
sco-websrvmg3/sco-websrvrmg3     598/tcp  # SCO Web Server Manager 3<BR>, sco-websrvrmg3<br><br>sco web server manager 3<br>
sco-websrvmg3/sco-websrvrmg3     598/udp  # SCO Web Server Manager 3<BR>, sco-websrvrmg3<br><br>sco web server manager 3<br>
acp                      599/tcp  # Aeolon Core Protocol<BR>
acp                      599/udp  # Aeolon Core Protocol<BR>
ipcserver                600/tcp  # Sun IPC server<BR>
ipcserver/ipcserver      600/udp  # Sun IPC server<BR>, ipcserver<br><br>sun ipc server<br>
urm                      606/tcp  # Cray Unified Resource Manager<BR>
urm                      606/udp  # Cray Unified Resource Manager<BR>
nqs                      607/tcp  # nqs<BR>
nqs                      607/udp  # nqs<BR>
sift-uft                 608/tcp  # Sender-Initiated/Unsolicited File Tx<BR>
sift-uft                 608/udp  # Sender-Initiated/Unsolicited File Tx<BR>
npmp-trap                609/tcp  # npmp-trap<BR>
npmp-trap                609/udp  # npmp-trap<BR>
npmp-local               610/tcp  # npmp-local<BR>
npmp-local               610/udp  # npmp-local<BR>
npmp-gui                 611/tcp  # npmp-gui<BR>
npmp-gui                 611/udp  # npmp-gui<BR>
hmmp-ind                 612/tcp  # HMMP Indication<BR>
hmmp-ind                 612/udp  # HMMP Indication<BR>
hmmp-op                  613/tcp  # HMMP Operation<BR>
hmmp-op                  613/udp  # HMMP Operation<BR>
sshell                   614/tcp  # SSLshell<BR>
sshell                   614/udp  # SSLshell<BR>
sco-inetmgr              615/tcp  # SCO Internet Configuration Manager<BR>
sco-inetmgr              615/udp  # SCO Internet Configuration Manager<BR>
sco-sysmgr               616/tcp  # SCO System Administration Server<BR>
sco-sysmgr               616/udp  # SCO System Administration Server<BR>
sco-dtmgr                617/tcp  # SCO Desktop Administration Server<BR>
sco-dtmgr                617/udp  # SCO Desktop Administration Server<BR>
dei-icda                 618/tcp  # DEI-ICDA<BR>
dei-icda                 618/udp  # DEI-ICDA<BR>
digital-evm              619/tcp  # Digital EVM<BR>
digital-evm              619/udp  # Digital EVM<BR>
sco-websrvrmgr           620/tcp  # SCO WebServer Manager<BR>
sco-websrvrmgr           620/udp  # SCO WebServer Manager<BR>
escp-ip                  621/tcp  # ESCP<BR>
escp-ip                  621/udp  # ESCP<BR>
collaborator             622/tcp  # Collaborator<BR>
collaborator             622/udp  # Collaborator<BR>
aux_bus_shunt            623/tcp  # Aux Bus Shunt<BR>
aux_bus_shunt            623/udp  # Aux Bus Shunt<BR>
cryptoadmin              624/tcp  # Crypto Admin<BR>
cryptoadmin              624/udp  # Crypto Admin<BR>
dec_dlm                  625/tcp  # DEC DLM<BR>
dec_dlm                  625/udp  # DEC DLM<BR>
asia                     626/tcp  # ASIA<BR>
asia                     626/udp  # ASIA<BR>
passgo-tivoli            627/tcp  # PassGo Tivoli<BR>
passgo-tivoli            627/udp  # PassGo Tivoli<BR>
qmqp                     628/tcp  # QMQP<BR>
qmqp/qmqp                628/udp  # QMQP<BR>, qmqp<br><br>qmqp<br>
3com-amp3                629/tcp  # 3Com AMP3<BR>
3com-amp3                629/udp  # 3Com AMP3<BR>
rda                      630/tcp  # RDA<BR>
rda                      630/udp  # RDA<BR>
ipp                      631/tcp  # Internet Printing Protocol<BR> 
ipp                      631/udp  # Internet Printing Protocol<BR> 
bmpp                     632/tcp  # bmpp<BR>
bmpp                     632/udp  # bmpp<BR>
servstat                 633/tcp  # Service Status update (Sterling Software)<BR>
servstat                 633/udp  # Service Status update (Sterling Software)<BR>
ginad                    634/tcp  # ginad<BR>
ginad                    634/udp  # ginad<BR>
linux-mountd/rlzdbase     635/tcp  # Linux mountd port<BR><br> Linux mountd rpc port, supports NFS-type services. <BR> Security Concerns: Popular attack target on Linux hosts, sue to buffer overflow vul on some Linux versions. <BR> , RLZ DBase<BR>
linux-mountd/rlzdbase/rlzdbase     635/udp  # Linux mountd port<BR><br> Linux mountd rpc port, supports NFS-type services. <BR> Security Concerns: Popular attack target on Linux hosts, sue to buffer overflow vul on some Linux versions. <BR> , RLZ DBase<BR>, rlzdbase<br><br>nfs mount service, rlz dbase<br>
ldaps                    636/tcp  # LDAP using TLS/SSL (was sldap)<BR>
ldaps                    636/udp  # LDAP using TLS/SSL (was sldap)<BR>
lanserver                637/tcp  # lanserver<BR>
lanserver                637/udp  # lanserver<BR>
mcns-sec                 638/tcp  # mcns-sec<BR>
mcns-sec                 638/udp  # mcns-sec<BR>
msdp                     639/tcp  # MSDP<BR>
msdp                     639/udp  # MSDP<BR>
entrust-sps              640/tcp  # Entrust-SPS<BR>
entrust-sps/entrust-sps     640/udp  # Entrust-SPS<BR>, entrust-sps<br><br>entrust-sps, pc-nfs dos authentication<br>
repcmd                   641/tcp  # RepCmd<BR>
repcmd                   641/udp  # RepCmd<BR>
esro-emsdp               642/tcp  # ESRO-EMSDP v1.3<BR>
esro-emsdp               642/udp  # ESRO-EMSDP v1.3<BR>
sanity                   643/tcp  # SANity<BR>
sanity                   643/udp  # SANity<BR>
dwr                      644/tcp  # dwr<BR>
dwr                      644/udp  # dwr<BR>
pssc                     645/tcp  # PCCS<BR>
pssc                     645/udp  # PCCS<BR>
ldp                      646/tcp  # 
ldp                      646/udp  # 
rrp                      648/tcp  # Registry Registrar Protocol (RRP)<BR>
rrp                      648/udp  # Registry Registrar Protocol (RRP)<BR>
aminet                   649/tcp  # Aminet<BR>
aminet                   649/udp  # Aminet<BR>
obex                     650/tcp  # OBEX<BR>
obex/obex                650/udp  # OBEX<BR>, obex<br><br>bw-nfs dos authentication, obex<br>
ieee-mms                 651/tcp  # IEEE MMS<BR>
ieee-mms                 651/udp  # IEEE MMS<BR>
udir-dtcp/udlr-dtcp      652/tcp  # UDLR_DTCP<BR>, udlr-dtcp<br><br>udlr_dtcp<br>
udir-dtcp/udlr-dtcp      652/udp  # UDLR_DTCP<BR>, udlr-dtcp<br><br>udlr_dtcp<br>
repscmd                  653/tcp  # RepCmd<BR>
repscmd                  653/udp  # RepCmd<BR>
aodv                     654/tcp  # AODV<BR>
aodv                     654/udp  # AODV<BR>
tinc                     655/tcp  # TINC<BR>
tinc                     655/udp  # TINC<BR>
spmp                     656/tcp  # SPMP<BR>
spmp                     656/udp  # SPMP<BR>
rmc                      657/tcp  # RMC<BR>
rmc                      657/udp  # RMC<BR>
tenfold                  658/tcp  # TenFold<BR>
tenfold                  658/udp  # TenFold<BR>
url-rendezvous           659/tcp  # URL Rendezvous<BR>
url-rendezvous           659/udp  # URL Rendezvous<BR>
mac-srvr-admin           660/tcp  # MacOS<BR>
mac-srvr-admin           660/udp  # MacOS<BR>
hap                      661/tcp  # HAP<BR>
hap                      661/udp  # HAP<BR>
pftp                     662/tcp  # PFTP<BR>
pftp                     662/udp  # PFTP<BR>
purenoise                663/tcp  # PureNoise<BR>
purenoise                663/udp  # PureNoise<BR>
secure-aux-bus           664/tcp  # Secure Aux Bus<BR>
secure-aux-bus           664/udp  # Secure Aux Bus<BR>
sun-dr                   665/tcp  # Sun DR<BR>
sun-dr                   665/udp  # Sun DR<BR>
mdqs/doom                666/tcp  # MDQS<BR>, doom Id Software<BR><br> Might get shot!! &lt;Grin Seriously, root-level exploit exists thru Doom on some Unix hosts (Linux confirmed). <BR> 
mdqs/doom                666/udp  # MDQS<BR>, doom Id Software<BR><br> Might get shot!! &lt;Grin Seriously, root-level exploit exists thru Doom on some Unix hosts (Linux confirmed). <BR> 
disclose                 667/tcp  # Campaign Contribution Disclosures<BR>
disclose                 667/udp  # Campaign Contribution Disclosures<BR>
mecomm                   668/tcp  # MeComm<BR>
mecomm                   668/udp  # MeComm<BR>
meregister               669/tcp  # MeRegister<BR>
meregister               669/udp  # MeRegister<BR>
vacdsm-sws               670/tcp  # VACDSM-SWS<BR>
vacdsm-sws               670/udp  # VACDSM-SWS<BR>
vacdsm-app               671/tcp  # VACDSM-APP<BR>
vacdsm-app               671/udp  # VACDSM-APP<BR>
vpps-qua                 672/tcp  # VPPS-QUA<BR>
vpps-qua                 672/udp  # VPPS-QUA<BR>
cimplex                  673/tcp  # CIMPLEX<BR>
cimplex                  673/udp  # CIMPLEX<BR>
acap                     674/tcp  # ACAP<BR>
acap                     674/udp  # ACAP<BR>
dctp                     675/tcp  # DCTP<BR>
dctp                     675/udp  # DCTP<BR>
vpps-via                 676/tcp  # VPPS Via<BR>
vpps-via                 676/udp  # VPPS Via<BR>
vpp                      677/tcp  # Virtual Presence Protocol<BR>
vpp                      677/udp  # Virtual Presence Protocol<BR>
ggf-ncp                  678/tcp  # GNU Generation Foundation NCP<BR>
ggf-ncp/ggf-ncp          678/udp  # GNU Generation Foundation NCP<BR>, ggf-ncp<br><br>gnu generation foundation ncp<br>
mrm                      679/tcp  # MRM<BR>
mrm                      679/udp  # MRM<BR>
entrust-aaas             680/tcp  # Entrust-aaas<BR>
entrust-aaas             680/udp  # Entrust-aaas<BR>
entrust-aams             681/tcp  # Entrust-aams<BR>
entrust-aams             681/udp  # Entrust-aams<BR>
xfr                      682/tcp  # XFR<BR>
xfr                      682/udp  # XFR<BR>
corba-iiop               683/tcp  # CORBA IIOP<BR>
corba-iiop               683/udp  # CORBA IIOP<BR>
corba-iiop-ssl           684/tcp  # CORBA IIOP SSL<BR>
corba-iiop-ssl           684/udp  # CORBA IIOP SSL<BR>
mdc-portmapper           685/tcp  # MDC Port Mapper<BR>
mdc-portmapper           685/udp  # MDC Port Mapper<BR>
hcp-wismar               686/tcp  # Hardware Control Protocol Wismar<BR>
hcp-wismar               686/udp  # Hardware Control Protocol Wismar<BR>
asipregistry             687/tcp  # asipregistry<BR>
asipregistry             687/udp  # asipregistry<BR>
realm-rusd               688/tcp  # REALM-RUSD<BR>
realm-rusd               688/udp  # REALM-RUSD<BR>
nmap                     689/tcp  # NMAP<BR>
nmap                     689/udp  # NMAP<BR>
vatp                     690/tcp  # VATP<BR>
vatp                     690/udp  # VATP<BR>
msexch-routing           691/tcp  # MS Exchange Routing<BR>
msexch-routing           691/udp  # MS Exchange Routing<BR>
hyperwave-isp            692/tcp  # Hyperwave-ISP<BR>
hyperwave-isp            692/udp  # Hyperwave-ISP<BR>
connedp/connendp         693/tcp  # connendp<BR>, connendp<br><br>connendp<br>
connedp/connendp         693/udp  # connendp<BR>, connendp<br><br>connendp<br>
ha-cluster               694/tcp  # ha-cluster<BR>
ha-cluster               694/udp  # ha-cluster<BR>
elcsd                    704/tcp  # errlog copy/server daemon<BR>
elcsd                    704/udp  # errlog copy/server daemon<BR>
agentx                   705/tcp  # AgentX<BR>
agentx                   705/udp  # AgentX<BR>
borland-dsj              707/tcp  # Borland DSJ<BR>
borland-dsj              707/udp  # Borland DSJ<BR>
entrust-kmsh             709/tcp  # Entrust Key Mgmt Service Handler<BR>
entrust-kmsh             709/udp  # Entrust Key Mgmt Service Handler<BR>
entrust-ash              710/tcp  # Entrust Admin Service Handler<BR>
entrust-ash              710/udp  # Entrust Admin Service Handler<BR>
cisco-tdp                711/tcp  # Cisco TDP<BR>
cisco-tdp                711/udp  # Cisco TDP<BR>
nt                       721/tcp  # Windows NT v3.5x Printer Ports<BR><br> Print jobs from NT v3.5x hosts are sourced from tcp 721-731, sequentially. Changed under NT v4.0, the lpd client now uses random source port between 512 and 1023. Was changed to provide higher consecutive print volume. <BR> 
                         /udp  # 
netviewdm1               729/tcp  # IBM NetView DM/6000 Server/Client<BR>
netviewdm1               729/udp  # IBM NetView DM/6000 Server/Client<BR>
netviewdm2               730/tcp  # IBM NetView DM/6000 send/tcp<BR>
netviewdm2               730/udp  # IBM NetView DM/6000 send/tcp<BR>
netviewdm3               731/tcp  # IBM NetView DM/6000 receive/tcp<BR>
netviewdm3               731/udp  # IBM NetView DM/6000 receive/tcp<BR>
netgw                    741/tcp  # netGW<BR>
netgw                    741/udp  # netGW<BR>
netrcs                   742/tcp  # Network based Rev. Cont. Sys.<BR>
netrcs                   742/udp  # Network based Rev. Cont. Sys.<BR>
flexlm                   744/tcp  # Flexible License Manager<BR>
flexlm                   744/udp  # Flexible License Manager<BR>
fujitsu-dev              747/tcp  # Fujitsu Device Control<BR>
fujitsu-dev              747/udp  # Fujitsu Device Control<BR>
ris-cm                   748/tcp  # Russell Info Sci Calendar Manager<BR>
ris-cm                   748/udp  # Russell Info Sci Calendar Manager<BR>
kerberos-adm             749/tcp  # kerberos administration<BR>
kerberos-adm/kerberos-adm     749/udp  # kerberos administration<BR>, kerberos-adm<br><br>kerberos administration, kerberos 5 admin/changepw<br>
rfile                    750/tcp  # rfile<BR>
rfile/loadav/kerberos-iv     750/udp  # rfile<BR>, loadav<BR>, Kerberos Version IV<BR>
pump                     751/tcp  # Pump<BR>
pump/pump                751/udp  # Pump<BR>, pump<br><br>kerberos `kadmin' (v4), kerberos authentication, kerberos admin server udp<br>
qrh                      752/tcp  # qrh<BR>
qrh                      752/udp  # qrh<BR>
rrh                      753/tcp  # rrh<BR>
rrh                      753/udp  # rrh<BR>
tell                     754/tcp  # send<BR>
tell/tell                754/udp  # send<BR>, tell<br><br>send<br>
nlogin                   758/tcp  # nlogin<BR>
nlogin                   758/udp  # nlogin<BR>
con                      759/tcp  # con<BR>
con                      759/udp  # con<BR>
ns                       760/tcp  # ns<BR>
ns/ns                    760/udp  # ns<BR>, ns<br><br><br>
rxe                      761/tcp  # rxe<BR>
rxe/rxe                  761/udp  # rxe<BR>, rxe<br><br><br>
quotad                   762/tcp  # quotad<BR>
quotad                   762/udp  # quotad<BR>
cycleserv                763/tcp  # cycleserv<BR>
cycleserv                763/udp  # cycleserv<BR>
omserv                   764/tcp  # omserv<BR>
omserv                   764/udp  # omserv<BR>
webster                  765/tcp  # webster<BR>
webster/webster          765/udp  # webster<BR>, webster<br><br><br>
phonebook                767/tcp  # phone<BR>
phonebook                767/udp  # phone<BR>
vid                      769/tcp  # vid<BR>
vid                      769/udp  # vid<BR>
cadlock                  770/tcp  # cadlock<BR>
cadlock                  770/udp  # cadlock<BR>
rtip                     771/tcp  # rtip<BR>
rtip                     771/udp  # rtip<BR>
cycleserv2               772/tcp  # cycleserv2<BR>
cycleserv2               772/udp  # cycleserv2<BR>
submit                   773/tcp  # submit<BR>
submit/notify            773/udp  # submit<BR>, Notify<BR>
rpasswd                  774/tcp  # rpasswd<BR>
acmaint_dbd              774/udp  # acmaint_dbd<BR>
entomb/sms_db            775/tcp  # entomb<BR>, Microsoft NT SMS Database<BR>
acmaint_transd/sms_db     775/udp  # acmaint_transd<BR>, Microsoft NT SMS Database<BR>
wpages                   776/tcp  # wpages<BR>
wpages                   776/udp  # wpages<BR>
multiling-http/sms_update     777/tcp  # Multiling HTTP<BR>, Microsoft NT SMS Update<BR>
multiling-http/sms_update     777/udp  # Multiling HTTP<BR>, Microsoft NT SMS Update<BR>
wpgs                     780/tcp  # wpgs<BR>
wpgs                     780/udp  # wpgs<BR>
concert                  786/tcp  # Concert<BR>
concert                  786/udp  # Concert<BR>
qsc                      787/tcp  # QSC<BR>
qsc                      787/udp  # QSC<BR>
off-explorer/mdbs_daemon     800/tcp  # Office Explorer<BR>Security Concerns: Allows remote viewing of a user's web cache. Traversal bug also allows viewing of files outside cache using "GET......" style commands. <BR> , mdbs_daemon<BR>
mdbs_daemon              800/udp  # mdbs_daemon<BR>
device                   801/tcp  # device<BR>
device                   801/udp  # device<BR>
fcp-tcp                  810/tcp  # FCP<BR>
fcp-udp                  810/udp  # FCP Datagram<BR>
itm-mcell-s              828/tcp  # itm-mcell-s<BR>
itm-mcell-s              828/udp  # itm-mcell-s<BR>
pkix-3-ca-ra             829/tcp  # PKIX-3 CA/RA<BR>
pkix-3-ca-ra             829/udp  # PKIX-3 CA/RA<BR>
rsync                    873/tcp  # rsync<BR>
rsync/rsync              873/udp  # rsync<BR>, rsync<br><br>rsync<br>
iclcnet-locate           886/tcp  # ICL coNETion locate server<BR>
iclcnet-locate           886/udp  # ICL coNETion locate server<BR>
iclcnet_svinfo           887/tcp  # ICL coNETion server info<BR>
iclcnet_svinfo           887/udp  # ICL coNETion server info<BR>
accessbuilder/cddbp      888/tcp  # AccessBuilder<BR>, CD Database Protocol<BR>
accessbuilder/accessbuilder     888/udp  # AccessBuilder<BR>, accessbuilder<br><br>accessbuilder<br>
fw-1_http/omginitialrefs     900/tcp  # Firewall-1 Web Access Port (CheckPoint)<BR><br> FW-1's remote user access/auth port via browser (http). Is alternative to telnet to FW's tcp 259. Via browser connection, user can auth and use all permitted web resources of the internal network. <BR> <br> FW-1 Ports: tcp 256, tcp/udp 259, udp 500, tcp 900 <BR> , OMG Initial Refs<BR>
omginitialrefs           900/udp  # OMG Initial Refs<BR>
smpnamers                901/tcp  # SMPNAMERES<BR>
smpnamers/smpnameres     901/udp  # SMPNAMERES<BR>, smpnameres<br><br>smpnameres<br>
ideaform-chat/ideafarm-chat     902/tcp  # IdeaFarm-Chat<BR>, ideafarm-chat<br><br>ideafarm-chat<br>
ideaform-chat/ideafarm-chat     902/udp  # IdeaFarm-Chat<BR>, ideafarm-chat<br><br>ideafarm-chat<br>
ideaform-catch/ideafarm-catch     903/tcp  # IdeaFarm-Catch<BR>, ideafarm-catch<br><br>ideafarm-catch<br>
ideaform-catch/ideafarm-catch     903/udp  # IdeaFarm-Catch<BR>, ideafarm-catch<br><br>ideafarm-catch<br>
xact-backup              911/tcp  # xact-backup<BR>
xact-backup              911/udp  # xact-backup<BR>
ftps-data                989/tcp  # Secure FTP Data Port (TLS/SSL)<BR>
ftps-data                989/udp  # Secure FTP Data Port (TLS/SSL)<BR>
ftps                     990/tcp  # Secure FTP Control Port (TLS/SSL)<BR>
ftps                     990/udp  # Secure FTP Control Port (TLS/SSL)<BR>
nas                      991/tcp  # Netnews Administration System<BR>
nas                      991/udp  # Netnews Administration System<BR>
telnets                  992/tcp  # telnet protocol over TLS/SSL<BR>
telnets                  992/udp  # telnet protocol over TLS/SSL<BR>
imaps                    993/tcp  # imap4 protocol over TLS/SSL<BR>
imaps/imaps              993/udp  # imap4 protocol over TLS/SSL<BR>, imaps<br><br>imap4 protocol over tls/ssl<br>
ircs                     994/tcp  # irc protocol over TLS/SSL<BR>
ircs                     994/udp  # irc protocol over TLS/SSL<BR>
pop3s                    995/tcp  # Secured POP3 (TLS/SSL) [was spop3]<BR><br> SSL-encrypted POP3 service for encrypted mail transfer. Also used by mail servers such as NT's Exchange Server for user auth. <BR> 
pop3s/pop3s              995/udp  # Secured POP3 (TLS/SSL) [was spop3]<BR><br> SSL-encrypted POP3 service for encrypted mail transfer. Also used by mail servers such as NT's Exchange Server for user auth. <BR> , pop3s<br><br>pop3 protocol over tls/ssl (was spop3)<br>
vsinet                   996/tcp  # vsinet<BR>
vsinet/vsinet            996/udp  # vsinet<BR>, vsinet<br><br>vsinet<br>
maitrd                   997/tcp  # maitrd<BR>
maitrd                   997/udp  # maitrd<BR>
busboy                   998/tcp  # busboy<BR>
puparp                   998/udp  # puparp<BR>
garcon/puprouter         999/tcp  # garcon<BR>, puprouter<BR>
applix/puprouter         999/udp  # Applix ac<BR>, puprouter<BR>
cadlock2                 1000/tcp  # Cadlock-2<BR>
cadlock2/ock             1000/udp  # Cadlock-2<BR>, ock<BR>
surf                     1010/tcp  # Surf<BR>
surf                     1010/udp  # Surf<BR>
--Buffer--               1023/tcp  # Unused Buffer Ports<BR>
--Buffer--               1023/udp  # Unused Buffer Ports<BR>
blackjack/listener       1025/tcp  # Network Blackjack<BR>, System V R3 listener; used by uucp<BR>
blackjack/listener/blackjack     1025/udp  # Network Blackjack<BR>, System V R3 listener; used by uucp<BR>, blackjack<br><br>network blackjack<br>
iad1                     1030/tcp  # BBN IAD<BR>
iad1                     1030/udp  # BBN IAD<BR>
iad2/inetinfo            1031/tcp  # BBN IAD<BR>, NT's Inetinfo<BR>
iad2                     1031/udp  # BBN IAD<BR>
iad3                     1032/tcp  # BBN IAD<BR>
iad3                     1032/udp  # BBN IAD<BR>
neod1                    1047/tcp  # Sun's NEO Object Request Broker<BR>
neod1                    1047/udp  # Sun's NEO Object Request Broker<BR>
neod2                    1048/tcp  # Sun's NEO Object Request Broker<BR>
neod2                    1048/udp  # Sun's NEO Object Request Broker<BR>
backdoor-port            1049/tcp  # Reported Backdoor<BR><br> Reported to have appeared on Linux hosts as a hacked backdoor, along with tcp 65534 (both open on same host). Little else known. <BR> 
                         /udp  # 
nim                      1058/tcp  # nim<BR>
nim                      1058/udp  # nim<BR>
nimreg                   1059/tcp  # nimreg<BR>
nimreg                   1059/udp  # nimreg<BR>
instl_boots              1067/tcp  # Instal Bootstrap Protocol Server<BR>
instl_boots              1067/udp  # Instal Bootstrap Protocol Server<BR>
instl_bootc              1068/tcp  # Instal Bootstrap Protocol Client<BR>
instl_bootc              1068/udp  # Instal Bootstrap Protocol Client<BR>
socks                    1080/tcp  # SOCKS<BR><br> SOCKS port, used to support outbound tcp services (FTP, HTTP, etc.). Vulnerable similar to FTP Bounce, in that attacker can connect to this port and "bounce" out to another internal host. Done to either reach a protected internal host or mask true source of attack. <BR> <br> Listen for connection attempts to this port -- good sign of port scans, SOCKS-probes, or bounce attacks. <BR> <br> Also a means to access restricted resources. Example: Bouncing off a MILNET gateway SOCKS port allows attacker to access web sites, etc. that were restricted only to .mil domain hosts. <BR> 
socks                    1080/udp  # SOCKS<BR><br> SOCKS port, used to support outbound tcp services (FTP, HTTP, etc.). Vulnerable similar to FTP Bounce, in that attacker can connect to this port and "bounce" out to another internal host. Done to either reach a protected internal host or mask true source of attack. <BR> <br> Listen for connection attempts to this port -- good sign of port scans, SOCKS-probes, or bounce attacks. <BR> <br> Also a means to access restricted resources. Example: Bouncing off a MILNET gateway SOCKS port allows attacker to access web sites, etc. that were restricted only to .mil domain hosts. <BR> 
ansoft-lm-1              1083/tcp  # Anasoft License Manager<BR>
ansoft-lm-1              1083/udp  # Anasoft License Manager<BR>
ansoft-lm-2              1084/tcp  # Anasoft License Manager<BR>
ansoft-lm-2              1084/udp  # Anasoft License Manager<BR>
webobjects               1085/tcp  # Web Objects<BR>
webobjects               1085/udp  # Web Objects<BR>
sunclustermgr            1097/tcp  # Sun Cluster Manager<BR>
sunclustermgr            1097/udp  # Sun Cluster Manager<BR>
rmiactivation            1098/tcp  # RMI Activation<BR>
rmiactivation            1098/udp  # RMI Activation<BR>
rmiregistry              1099/tcp  # RMI Registry<BR>
rmiregistry              1099/udp  # RMI Registry<BR>
kpop                     1109/tcp  # Pop with Kerberos<BR>
                         /udp  # 
nfsd-status              1110/tcp  # NFSD cluster status info<BR>
nfsd-keepalive           1110/udp  # NFSD client status info<BR>
lmsocialserver           1111/tcp  # LM Social Server<BR>
lmsocialserver           1111/udp  # LM Social Server<BR>
mini-sql                 1114/tcp  # Mini SQL<BR>
mini-sql                 1114/udp  # Mini SQL<BR>
murray                   1123/tcp  # Murray<BR>
murray                   1123/udp  # Murray<BR>
nfa                      1155/tcp  # Network File Access<BR>
nfa                      1155/udp  # Network File Access<BR>
health-polling           1161/tcp  # Health Polling<BR>
health-polling           1161/udp  # Health Polling<BR>
health-trap              1162/tcp  # Health Trap<BR>
health-trap              1162/udp  # Health Trap<BR>
                         /tcp  # 
phone                    1167/udp  # Internet Phone<BR>
mc-client                1180/tcp  # Millicent Client Proxy<BR>
mc-client                1180/udp  # Millicent Client Proxy<BR>
scol                     1200/tcp  # SCOL<BR>
scol                     1200/udp  # SCOL<BR>
caiccipc                 1202/tcp  # caiccipc<BR>
caiccipc                 1202/udp  # caiccipc<BR>
lupa                     1212/tcp  # lupa<BR>
lupa                     1212/udp  # lupa<BR>
scanstat-1               1215/tcp  # scanSTAT 1.0<BR>
scanstat-1               1215/udp  # scanSTAT 1.0<BR>
nerv                     1222/tcp  # SNI R&amp;D network<BR>
nerv                     1222/udp  # SNI R&amp;D network<BR>
search-agent             1234/tcp  # Infoseek Search Agent<BR>
search-agent             1234/udp  # Infoseek Search Agent<BR>
vosiac                   1235/tcp  # Vosiac<BR><br> Audio/video protocol based on Video Datagram Protocol (VDP). Also uses udp 61801-61821. <BR> 
                         /udp  # 
nmsd                     1239/tcp  # NMSD<BR>
nmsd                     1239/udp  # NMSD<BR>
subsevel-infection       1243/tcp  # SubSevel Infection Port<BR><br> One of the known SubSeven tcp control ports. Others include tcp 6711, 6712, 6713, 6776. Default is tcp 27374. <BR> 
                         /udp  # 
hermes                   1248/tcp  # hermes<BR>
hermes                   1248/udp  # hermes<BR>
h323hostcallsc           1300/tcp  # H.323 Host Call Secure<BR>
h323hostcallsc           1300/udp  # H.323 Host Call Secure<BR>
husky                    1310/tcp  # Husky<BR>
husky                    1310/udp  # Husky<BR>
rxmon                    1311/tcp  # RxMon<BR>
rxmon                    1311/udp  # RxMon<BR>
sti-envision             1312/tcp  # STI Envision<BR>
sti-envision             1312/udp  # STI Envision<BR>
bmc_patroldb/dynamo-db     1313/tcp  # BMC_Patrol Database<BR>, Dynamo Database<BR><br> Test Dynamo app's database port. Used on Dynamo server for testing (provides "some" db for the Dynamo app to test functionality with upon initial install. Used when a live db is unavailable or undesirable for test. <BR> 
bmc_patroldb/bmc-patroldb     1313/udp  # BMC_Patrol Database<BR>, bmc-patroldb<br><br>bmc_patroldb<br>
pdps                     1314/tcp  # Photoscript Distributed Print System<BR>
pdps                     1314/udp  # Photoscript Distributed Print System<BR>
panja-axbnet             1320/tcp  # Panja-AXBNET<BR>
panja-axbnet             1320/udp  # Panja-AXBNET<BR>
pip                      1321/tcp  # 
pip                      1321/udp  # 
digital-notary           1335/tcp  # Digital Notary Protocol<BR>
digital-notary           1335/udp  # Digital Notary Protocol<BR>
VMOTelnet                1342/tcp  # VMODEM telnet redirect<BR>
VMOTelnet                1342/udp  # VMODEM telnet redirect<BR>
vpjp                     1345/tcp  # VPJP<BR>
vpjp                     1345/udp  # VPJP<BR>
alta-ana-lm              1346/tcp  # Alta Analytics License Manager<BR>
alta-ana-lm              1346/udp  # Alta Analytics License Manager<BR>
bbn-mmc                  1347/tcp  # Multimedia conferencing<BR>
bbn-mmc                  1347/udp  # Multimedia conferencing<BR>
bbn-mmx                  1348/tcp  # Multimedia conferencing<BR>
bbn-mmx                  1348/udp  # Multimedia conferencing<BR>
sbook                    1349/tcp  # Registration Network Protocol<BR>
sbook                    1349/udp  # Registration Network Protocol<BR>
editbench                1350/tcp  # Registration Network Protocol<BR>
editbench                1350/udp  # Registration Network Protocol<BR>
equationbuilder          1351/tcp  # Digital Tool Works (MIT)<BR>
equationbuilder          1351/udp  # Digital Tool Works (MIT)<BR>
lotusnote                1352/tcp  # Lotus Notes<BR><br> Lotus Notes provides a range of services on tcp 1352, including email (others include replication to DRA-mirrored systems, app client/server calls, etc). Vulnerable to much of same attacks poss. on tcp 25, including data disclosure, modification, and forgery, plus DOS flooding. <BR> 
lotusnote                1352/udp  # Lotus Notes<BR><br> Lotus Notes provides a range of services on tcp 1352, including email (others include replication to DRA-mirrored systems, app client/server calls, etc). Vulnerable to much of same attacks poss. on tcp 25, including data disclosure, modification, and forgery, plus DOS flooding. <BR> 
relief                   1353/tcp  # Relief Consulting<BR>
relief                   1353/udp  # Relief Consulting<BR>
rightbrain               1354/tcp  # RightBrain Software<BR>
rightbrain               1354/udp  # RightBrain Software<BR>
cuillamartin             1356/tcp  # CuillaMartin Company<BR>
cuillamartin             1356/udp  # CuillaMartin Company<BR>
pegboard                 1357/tcp  # Electronic PegBoard<BR>
pegboard                 1357/udp  # Electronic PegBoard<BR>
connlcli                 1358/tcp  # CONNLCLI<BR>
connlcli                 1358/udp  # CONNLCLI<BR>
ftsrv                    1359/tcp  # FTSRV<BR>
ftsrv                    1359/udp  # FTSRV<BR>
mimer                    1360/tcp  # MIMER<BR>
mimer                    1360/udp  # MIMER<BR>
linx                     1361/tcp  # LinX<BR>
linx                     1361/udp  # LinX<BR>
timeflies                1362/tcp  # TimeFlies<BR>
timeflies                1362/udp  # TimeFlies<BR>
ndm-requester            1363/tcp  # Network DataMover Requester<BR>
ndm-requester            1363/udp  # Network DataMover Requester<BR>
ndm-server               1364/tcp  # Network DataMover Server<BR>
ndm-server               1364/udp  # Network DataMover Server<BR>
adapt-sna                1365/tcp  # Network Software Associates<BR>
adapt-sna                1365/udp  # Network Software Associates<BR>
netware-csp              1366/tcp  # Novell NetWare Comm Service Platform<BR>
netware-csp              1366/udp  # Novell NetWare Comm Service Platform<BR>
dcs                      1367/tcp  # DCS<BR>
dcs                      1367/udp  # DCS<BR>
screencast               1368/tcp  # ScreenCast<BR>
screencast               1368/udp  # ScreenCast<BR>
gv-us                    1369/tcp  # GlobalView to Unix Shell<BR>
gv-us                    1369/udp  # GlobalView to Unix Shell<BR>
us-gv                    1370/tcp  # Unix Shell to GlobalView<BR>
us-gv                    1370/udp  # Unix Shell to GlobalView<BR>
fc-cli                   1371/tcp  # Fujitsu Config Protocol<BR>
fc-cli                   1371/udp  # Fujitsu Config Protocol<BR>
fc-ser                   1372/tcp  # Fujitsu Config Protocol<BR>
fc-ser                   1372/udp  # Fujitsu Config Protocol<BR>
chromagrafx              1373/tcp  # Chromagrafx<BR>
chromagrafx              1373/udp  # Chromagrafx<BR>
molly                    1374/tcp  # EPI Software Systems<BR>
molly                    1374/udp  # EPI Software Systems<BR>
bytex                    1375/tcp  # Bytex<BR>
bytex                    1375/udp  # Bytex<BR>
ibm-pps                  1376/tcp  # IBM Person to Person Software<BR>
ibm-pps                  1376/udp  # IBM Person to Person Software<BR>
cichlid                  1377/tcp  # Cichlid License Manager<BR>
cichlid                  1377/udp  # Cichlid License Manager<BR>
elan                     1378/tcp  # Elan License Manager<BR>
elan                     1378/udp  # Elan License Manager<BR>
dbreporter               1379/tcp  # Integrity Solutions<BR>
dbreporter               1379/udp  # Integrity Solutions<BR>
telesis-licman           1380/tcp  # Telesis Network License Manager<BR>
telesis-licman           1380/udp  # Telesis Network License Manager<BR>
apple-licman             1381/tcp  # Apple Network License Manager<BR>
apple-licman             1381/udp  # Apple Network License Manager<BR>
udt_os                   1382/tcp  # udt_os<BR>
udt_os                   1382/udp  # udt_os<BR>
gwha                     1383/tcp  # GW Hannaway Network License Manager<BR>
gwha                     1383/udp  # GW Hannaway Network License Manager<BR>
os-licman                1384/tcp  # Objective Solutions License Manager<BR>
os-licman                1384/udp  # Objective Solutions License Manager<BR>
atex_elmd                1385/tcp  # Atex Publishing License Manager<BR>
atex_elmd                1385/udp  # Atex Publishing License Manager<BR>
checksum                 1386/tcp  # CheckSum License Manager<BR>
checksum                 1386/udp  # CheckSum License Manager<BR>
cadsi-lm                 1387/tcp  # CAD Software Inc LM<BR>
cadsi-lm                 1387/udp  # CAD Software Inc LM<BR>
objective-dbc            1388/tcp  # Objective Solutions DataBase Cache<BR>
objective-dbc            1388/udp  # Objective Solutions DataBase Cache<BR>
iclpv-dm                 1389/tcp  # Document Manager<BR>
iclpv-dm                 1389/udp  # Document Manager<BR>
iclpv-sc                 1390/tcp  # Storage Controller<BR>
iclpv-sc                 1390/udp  # Storage Controller<BR>
iclpv-sas                1391/tcp  # Storage Access Server<BR>
iclpv-sas                1391/udp  # Storage Access Server<BR>
iclpv-pm                 1392/tcp  # Print Manager<BR>
iclpv-pm                 1392/udp  # Print Manager<BR>
iclpv-nls                1393/tcp  # Network Log Server<BR>
iclpv-nls                1393/udp  # Network Log Server<BR>
iclpv-nlc                1394/tcp  # Network Log Client<BR>
iclpv-nlc                1394/udp  # Network Log Client<BR>
iclpv-wsm                1395/tcp  # PC Workstation Manager software<BR>
iclpv-wsm                1395/udp  # PC Workstation Manager software<BR>
dvl-activemail           1396/tcp  # DVL Active Mail<BR>
dvl-activemail           1396/udp  # DVL Active Mail<BR>
audio-activmail          1397/tcp  # Audio Active Mail<BR>
audio-activmail          1397/udp  # Audio Active Mail<BR>
video-activmail          1398/tcp  # Video Active Mail<BR>
video-activmail          1398/udp  # Video Active Mail<BR>
cadkey-licman            1399/tcp  # Cadkey License Manager<BR>
cadkey-licman            1399/udp  # Cadkey License Manager<BR>
cadkey-tablet            1400/tcp  # Cadkey Tablet Daemon<BR>
cadkey-tablet            1400/udp  # Cadkey Tablet Daemon<BR>
goldleaf-licman          1401/tcp  # Goldleaf License Manager<BR>
goldleaf-licman          1401/udp  # Goldleaf License Manager<BR>
prm-sm-np                1402/tcp  # Prospero Resource Manager<BR>
prm-sm-np                1402/udp  # Prospero Resource Manager<BR>
prm-nm-np                1403/tcp  # Prospero Resource Manager<BR>
prm-nm-np                1403/udp  # Prospero Resource Manager<BR>
igi-lm                   1404/tcp  # Infinite Graphics License Manager<BR>
igi-lm                   1404/udp  # Infinite Graphics License Manager<BR>
ibm-res                  1405/tcp  # IBM Remote Execution Starter<BR>
ibm-res                  1405/udp  # IBM Remote Execution Starter<BR>
netlabs-lm               1406/tcp  # NetLabs License Manager<BR>
netlabs-lm               1406/udp  # NetLabs License Manager<BR>
dbsa-lm                  1407/tcp  # DBSA License Manager<BR>
dbsa-lm                  1407/udp  # DBSA License Manager<BR>
sophia-lm                1408/tcp  # Sophia License Manager<BR>
sophia-lm                1408/udp  # Sophia License Manager<BR>
here-lm                  1409/tcp  # Here License Manager<BR>
here-lm                  1409/udp  # Here License Manager<BR>
hiq                      1410/tcp  # HiQ License Manager<BR>
hiq                      1410/udp  # HiQ License Manager<BR>
af                       1411/tcp  # AudioFile<BR>
af                       1411/udp  # AudioFile<BR>
innosys                  1412/tcp  # InnoSys<BR>
innosys                  1412/udp  # InnoSys<BR>
innosys-acl              1413/tcp  # Innosys-ACL<BR>
innosys-acl              1413/udp  # Innosys-ACL<BR>
ibm-mqseries             1414/tcp  # IBM MQSeries<BR>
ibm-mqseries             1414/udp  # IBM MQSeries<BR>
dbstar                   1415/tcp  # DBStar<BR>
dbstar                   1415/udp  # DBStar<BR>
novell-lu6.2             1416/tcp  # Novell LU6.2<BR>
novell-lu6.2             1416/udp  # Novell LU6.2<BR>
timbuktu-srv1            1417/tcp  # Timbuktu Service 1 Port<BR>
timbuktu-srv1            1417/udp  # Timbuktu Service 1 Port<BR>
timbuktu-srv2            1418/tcp  # Timbuktu Service 2 Port<BR>
timbuktu-srv2            1418/udp  # Timbuktu Service 2 Port<BR>
timbuktu-srv3            1419/tcp  # Timbuktu Service 3 Port<BR>
timbuktu-srv3            1419/udp  # Timbuktu Service 3 Port<BR>
timbuktu-srv4            1420/tcp  # Timbuktu Service 4 Port<BR>
timbuktu-srv4            1420/udp  # Timbuktu Service 4 Port<BR>
gandalf-lm               1421/tcp  # Gandalf License Manager<BR>
gandalf-lm               1421/udp  # Gandalf License Manager<BR>
autodesk-lm              1422/tcp  # Autodesk License Manager<BR>
autodesk-lm              1422/udp  # Autodesk License Manager<BR>
essbase                  1423/tcp  # Essbase Arbor Software<BR>
essbase                  1423/udp  # Essbase Arbor Software<BR>
hybrid                   1424/tcp  # Hybrid Encryption Protocol<BR>
hybrid                   1424/udp  # Hybrid Encryption Protocol<BR>
zion-lm                  1425/tcp  # Zion Software License Manager<BR>
zion-lm                  1425/udp  # Zion Software License Manager<BR>
sais                     1426/tcp  # Satellite-data Acquisition System 1<BR>
sais                     1426/udp  # Satellite-data Acquisition System 1<BR>
mloadd                   1427/tcp  # mloadd monitoring tool<BR>
mloadd                   1427/udp  # mloadd monitoring tool<BR>
informatik-lm            1428/tcp  # Informatik License Manager<BR>
informatik-lm            1428/udp  # Informatik License Manager<BR>
nms                      1429/tcp  # Hypercom NMS<BR>
nms                      1429/udp  # Hypercom NMS<BR>
tpdu                     1430/tcp  # Hypercom TPDU<BR>
tpdu                     1430/udp  # Hypercom TPDU<BR>
rgtp                     1431/tcp  # Reverse Gossip Transport<BR>
rgtp                     1431/udp  # Reverse Gossip Transport<BR>
blueberry-lm             1432/tcp  # Blueberry Software License Manager<BR>
blueberry-lm             1432/udp  # Blueberry Software License Manager<BR>
ms-sql-s                 1433/tcp  # Microsoft SQL Server<BR><br> Also known as "TDS" for "Tabular Data Stream" DB-library, used by Microsoft's SQL server. <BR> 
ms-sql-s                 1433/udp  # Microsoft SQL Server<BR><br> Also known as "TDS" for "Tabular Data Stream" DB-library, used by Microsoft's SQL server. <BR> 
ms-sql-m                 1434/tcp  # Microsoft SQL Monitor<BR>
ms-sql-m                 1434/udp  # Microsoft SQL Monitor<BR>
ibm-cics                 1435/tcp  # IBM CICS<BR>
ibm-cics                 1435/udp  # IBM CICS<BR>
saism                    1436/tcp  # Satellite-data Acquisition System 2<BR>
saism                    1436/udp  # Satellite-data Acquisition System 2<BR>
tabula                   1437/tcp  # Tabula<BR>
tabula                   1437/udp  # Tabula<BR>
eicon-server             1438/tcp  # Eicon Security Agent/Server<BR>
eicon-server             1438/udp  # Eicon Security Agent/Server<BR>
eicon-x25                1439/tcp  # Eicon X25/SNA Gateway<BR>
eicon-x25                1439/udp  # Eicon X25/SNA Gateway<BR>
eicon-slp                1440/tcp  # Eicon Service Location Protocol<BR>
eicon-slp                1440/udp  # Eicon Service Location Protocol<BR>
cadis-1                  1441/tcp  # Cadis License Management<BR>
cadis-1                  1441/udp  # Cadis License Management<BR>
cadis-2                  1442/tcp  # Cadis License Management<BR>
cadis-2                  1442/udp  # Cadis License Management<BR>
ies-lm                   1443/tcp  # Integrated Engineering Software<BR>
ies-lm                   1443/udp  # Integrated Engineering Software<BR>
marcam-lm                1444/tcp  # Marcam License Management<BR>
marcam-lm                1444/udp  # Marcam License Management<BR>
proxima-lm               1445/tcp  # Proxima License Manager<BR>
proxima-lm               1445/udp  # Proxima License Manager<BR>
ora-lm                   1446/tcp  # Optical Research Associates LM<BR>
ora-lm                   1446/udp  # Optical Research Associates LM<BR>
apri-lm                  1447/tcp  # Applied Parallel Research LM<BR>
apri-lm                  1447/udp  # Applied Parallel Research LM<BR>
oc-lm                    1448/tcp  # OpenConnect License Manager<BR>
oc-lm                    1448/udp  # OpenConnect License Manager<BR>
peport                   1449/tcp  # PEport<BR>
peport                   1449/udp  # PEport<BR>
dwf                      1450/tcp  # Tandem Distrib Workbench Facility<BR>
dwf                      1450/udp  # Tandem Distrib Workbench Facility<BR>
infoman                  1451/tcp  # IBM Info Management<BR>
infoman                  1451/udp  # IBM Info Management<BR>
gtegsc-lm                1452/tcp  # GTE Government Systems LM<BR>
gtegsc-lm                1452/udp  # GTE Government Systems LM<BR>
genie-lm                 1453/tcp  # Genie License Manager<BR>
genie-lm                 1453/udp  # Genie License Manager<BR>
interhdl_elmd            1454/tcp  # interHDL License Manager<BR>
interhdl_elmd            1454/udp  # interHDL License Manager<BR>
esl-lm                   1455/tcp  # ESL License Manager<BR>
esl-lm                   1455/udp  # ESL License Manager<BR>
dca                      1456/tcp  # DCA<BR>
dca                      1456/udp  # DCA<BR>
valisys-lm               1457/tcp  # Valisys License Manager<BR>
valisys-lm               1457/udp  # Valisys License Manager<BR>
nrcabq-lm                1458/tcp  # Nichols Research Corp.<BR>
nrcabq-lm                1458/udp  # Nichols Research Corp.<BR>
proshare1                1459/tcp  # Proshare Notebook Application<BR>
proshare1                1459/udp  # Proshare Notebook Application<BR>
proshare2                1460/tcp  # Proshare Notebook Application<BR>
proshare2                1460/udp  # Proshare Notebook Application<BR>
ibm_wrless_lan           1461/tcp  # IBM Wireless LAN<BR>
ibm_wrless_lan           1461/udp  # IBM Wireless LAN<BR>
world-lm                 1462/tcp  # World License Manager<BR>
world-lm                 1462/udp  # World License Manager<BR>
nucleus                  1463/tcp  # Nucleus<BR>
nucleus                  1463/udp  # Nucleus<BR>
msl_lmd                  1464/tcp  # MSL License Manager<BR>
msl_lmd                  1464/udp  # MSL License Manager<BR>
pipes                    1465/tcp  # Pipes Platform<BR>
pipes/pipes              1465/udp  # Pipes Platform<BR>, pipes<br><br>pipes platform  mfarlin@peerlogic.com<br>
oceansoft-lm             1466/tcp  # Ocean Software License Manager<BR>
oceansoft-lm             1466/udp  # Ocean Software License Manager<BR>
csdmbase                 1467/tcp  # CSDMBASE<BR>
csdmbase                 1467/udp  # CSDMBASE<BR>
csdm                     1468/tcp  # CSDM<BR>
csdm                     1468/udp  # CSDM<BR>
aal-lm                   1469/tcp  # Active Analysis Limited LM<BR>
aal-lm                   1469/udp  # Active Analysis Limited LM<BR>
uaiact                   1470/tcp  # Universal Analytics<BR>
uaiact                   1470/udp  # Universal Analytics<BR>
csdmbase                 1471/tcp  # csdmbase<BR>
csdmbase                 1471/udp  # csdmbase<BR>
csdm                     1472/tcp  # csdm<BR>
csdm                     1472/udp  # csdm<BR>
openmath                 1473/tcp  # OpenMath<BR>
openmath                 1473/udp  # OpenMath<BR>
telefinder               1474/tcp  # Telefinder<BR>
telefinder               1474/udp  # Telefinder<BR>
taligent-lm              1475/tcp  # Taligent License Manager<BR>
taligent-lm              1475/udp  # Taligent License Manager<BR>
clvm-cfg                 1476/tcp  # clvm-cfg<BR>
clvm-cfg                 1476/udp  # clvm-cfg<BR>
ms-sna-server            1477/tcp  # ms-sna-server<BR>
ms-sna-server            1477/udp  # ms-sna-server<BR>
ms-sna-base              1478/tcp  # ms-sna-base<BR>
ms-sna-base              1478/udp  # ms-sna-base<BR>
dberegister              1479/tcp  # dberegister<BR>
dberegister              1479/udp  # dberegister<BR>
pacerforum               1480/tcp  # PacerForum<BR>
pacerforum               1480/udp  # PacerForum<BR>
airs                     1481/tcp  # AIRS<BR>
airs                     1481/udp  # AIRS<BR>
miteksys-lm              1482/tcp  # Miteksys License Manager<BR>
miteksys-lm              1482/udp  # Miteksys License Manager<BR>
afs                      1483/tcp  # AFS License Manager<BR>
afs                      1483/udp  # AFS License Manager<BR>
confluent                1484/tcp  # Confluent License Manager<BR>
confluent                1484/udp  # Confluent License Manager<BR>
lansource                1485/tcp  # LANSource<BR>
lansource                1485/udp  # LANSource<BR>
nms_topo_serv            1486/tcp  # nms_topo_serv<BR>
nms_topo_serv            1486/udp  # nms_topo_serv<BR>
localinfosrvr            1487/tcp  # LocalInfoSrvr<BR>
localinfosrvr            1487/udp  # LocalInfoSrvr<BR>
docstor                  1488/tcp  # DocStor<BR>
docstor                  1488/udp  # DocStor<BR>
dmdocbroker              1489/tcp  # dmdocbroker<BR>
dmdocbroker              1489/udp  # dmdocbroker<BR>
vocaltec/insitu-conf     1490/tcp  # VocalTec Internet Phone<BR><br> Video-Teleconferencing. Also uses tcp 6670 &amp; 25793, tcp/udp 22555. <BR> , insitu-conf<BR>
insitu-conf              1490/udp  # insitu-conf<BR>
anynetgateway            1491/tcp  # Anynet Gateway<BR>
anynetgateway            1491/udp  # Anynet Gateway<BR>
stone-design-1           1492/tcp  # Stone Design 1<BR>
stone-design-1           1492/udp  # Stone Design 1<BR>
netmap_lm                1493/tcp  # Netmap License Manager<BR>
netmap_lm                1493/udp  # Netmap License Manager<BR>
ica/winframe             1494/tcp  # ICA<BR>, WinFrame remote LAN service<br> Used on MS hosts for ICA Citrix Client<BR> 
ica                      1494/udp  # ICA<BR>
cvc                      1495/tcp  # CVC<BR>
cvc                      1495/udp  # CVC<BR>
liberty-lm               1496/tcp  # Liberty License Manager<BR>
liberty-lm               1496/udp  # Liberty License Manager<BR>
rfx-lm                   1497/tcp  # RFX License Manager<BR>
rfx-lm                   1497/udp  # RFX License Manager<BR>
watcom-sql/sybase-sqlany     1498/tcp  # Watcom SQL<BR>, Sybase SQL Any<BR>
watcom-sql/sybase-sqlany     1498/udp  # Watcom SQL<BR>, Sybase SQL Any<BR>
fhc                      1499/tcp  # Federico Heinz Consultora<BR>
fhc                      1499/udp  # Federico Heinz Consultora<BR>
vlsi-lm                  1500/tcp  # VLSI License Manager<BR>
vlsi-lm                  1500/udp  # VLSI License Manager<BR>
saiscm                   1501/tcp  # Satellite-data Acquisition System 3<BR>
saiscm                   1501/udp  # Satellite-data Acquisition System 3<BR>
shivadiscovery           1502/tcp  # Shiva<BR>
shivadiscovery           1502/udp  # Shiva<BR>
imtc-mcs/netmeeting      1503/tcp  # Databeam T-120<BR><br> Used by multimedia collaborative apps such as NetMeeting to establish and control a collaborative session. <BR> , Microsoft NetMeeting<BR>
imtc-mcs                 1503/udp  # Databeam T-120<BR><br> Used by multimedia collaborative apps such as NetMeeting to establish and control a collaborative session. <BR> 
evb-elm                  1504/tcp  # EVB Software Engineering License Mgr<BR>
evb-elm                  1504/udp  # EVB Software Engineering License Mgr<BR>
funkproxy                1505/tcp  # Funk Software, Inc.<BR>
funkproxy                1505/udp  # Funk Software, Inc.<BR>
utcd                     1506/tcp  # Universal Time daemon (utcd)<BR>
utcd                     1506/udp  # Universal Time daemon (utcd)<BR>
symplex                  1507/tcp  # symplex<BR>
symplex                  1507/udp  # symplex<BR>
diagmond                 1508/tcp  # Diagnostic Monitor<BR>
diagmond                 1508/udp  # Diagnostic Monitor<BR>
robcad-lm                1509/tcp  # Robcad License Manager<BR>
robcad-lm                1509/udp  # Robcad License Manager<BR>
mvx-lm                   1510/tcp  # Midland Valley Exploration LM<BR>
mvx-lm                   1510/udp  # Midland Valley Exploration LM<BR>
3l-l1                    1511/tcp  # 3l-l1<BR>
3l-l1                    1511/udp  # 3l-l1<BR>
wins                     1512/tcp  # Windows Internet Name Service (WINS)<BR><br> Was reserved by Microsoft for WINS, however WINS actually uses old ARPAnet Naming Service port (tcp 42). <BR> 
wins                     1512/udp  # Windows Internet Name Service (WINS)<BR><br> Was reserved by Microsoft for WINS, however WINS actually uses old ARPAnet Naming Service port (tcp 42). <BR> 
fujitsu-dtc              1513/tcp  # Fujitsu Systems Bus. of America, Inc<BR>
fujitsu-dtc              1513/udp  # Fujitsu Systems Bus. of America, Inc<BR>
fujitsu-dtcns            1514/tcp  # Fujitsu Systems Business of America, Inc<BR>
fujitsu-dtcns            1514/udp  # Fujitsu Systems Business of America, Inc<BR>
ifor-protocol            1515/tcp  # ifor-protocol<BR>
ifor-protocol            1515/udp  # ifor-protocol<BR>
vpad                     1516/tcp  # Virtual Places Audio data<BR>
vpad                     1516/udp  # Virtual Places Audio data<BR>
vpac                     1517/tcp  # Virtual Places Audio control<BR>
vpac                     1517/udp  # Virtual Places Audio control<BR>
vpvd                     1518/tcp  # Virtual Places Video data<BR>
vpvd                     1518/udp  # Virtual Places Video data<BR>
vpvc                     1519/tcp  # Virtual Places Video control<BR>
vpvc                     1519/udp  # Virtual Places Video control<BR>
atm-zip-office           1520/tcp  # ATM Zip Office<BR>
atm-zip-office           1520/udp  # ATM Zip Office<BR>
ncube-lm/sqlnet          1521/tcp  # nCube License Manager<BR>, SQLnet<BR>
ncube-lm/sqlnet          1521/udp  # nCube License Manager<BR>, SQLnet<BR>
ricardo-lm               1522/tcp  # Ricardo North America LM<BR>
ricardo-lm               1522/udp  # Ricardo North America LM<BR>
sqlnet2/cichild-lm       1523/tcp  # SQLnet2<BR><br> Oracle connection thru firewall. <BR> , cichild<BR>
cichild-lm               1523/udp  # cichild<BR>
ingreslock               1524/tcp  # ingres<BR><br> Popular tcp port for backdoor (eg: Trinoo relay slave). Watch for connection attempts to it at perimeter and within network. <BR> 
ingreslock               1524/udp  # ingres<BR><br> Popular tcp port for backdoor (eg: Trinoo relay slave). Watch for connection attempts to it at perimeter and within network. <BR> 
orasrv/prospero-np       1525/tcp  # Oracle<BR>, Prospero Directory Service non-priv<BR>
archie/orasrv/prospero-np/orasrv     1525/udp  # <br> Old search engine for anomymous ftp archieves; replaced by web and its search engines. Unlikely to still find in use.<BR>, Oracle<BR>, Prospero Directory Service non-priv<BR>, orasrv<br><br>prospero directory service non-priv, oracle<br>
pdap-np/sqlnet           1526/tcp  # Prospero Data Access Prot non-priv<BR>, SQLnet<BR>
pdap-np/sqlnet           1526/udp  # Prospero Data Access Prot non-priv<BR>, SQLnet<BR>
tlisrv                   1527/tcp  # Oracle<BR>
tlisrv                   1527/udp  # Oracle<BR>
mciautoreg               1528/tcp  # micautoreg<BR>
mciautoreg               1528/udp  # micautoreg<BR>
coauthor                 1529/tcp  # Oracle<BR>
coauthor/coauthor        1529/udp  # Oracle<BR>, coauthor<br><br>oracle<br>
rap-service              1530/tcp  # rap-service<BR>
rap-service              1530/udp  # rap-service<BR>
rap-listen               1531/tcp  # rap-listen<BR>
rap-listen               1531/udp  # rap-listen<BR>
miroconnect              1532/tcp  # miroconnect<BR>
miroconnect              1532/udp  # miroconnect<BR>
virtual-places           1533/tcp  # Virtual Places Software<BR>
virtual-places           1533/udp  # Virtual Places Software<BR>
micromuse-lm             1534/tcp  # Micromuse License Manager<BR>
micromuse-lm             1534/udp  # Micromuse License Manager<BR>
ampr-info                1535/tcp  # ampr-info<BR>
ampr-info                1535/udp  # ampr-info<BR>
ampr-inter               1536/tcp  # ampr-inter<BR>
ampr-inter               1536/udp  # ampr-inter<BR>
sdsc-lm                  1537/tcp  # isi-lm<BR>
sdsc-lm                  1537/udp  # isi-lm<BR>
3ds-lm                   1538/tcp  # 3ds-lm<BR>
3ds-lm                   1538/udp  # 3ds-lm<BR>
intellistor-lm           1539/tcp  # Intellistor License Manager<BR>
intellistor-lm           1539/udp  # Intellistor License Manager<BR>
rds                      1540/tcp  # rds<BR>
rds                      1540/udp  # rds<BR>
rds2                     1541/tcp  # rds2<BR>
rds2                     1541/udp  # rds2<BR>
gridgen-elmd             1542/tcp  # gridgen-elmd<BR>
gridgen-elmd             1542/udp  # gridgen-elmd<BR>
simba-cs                 1543/tcp  # simba-cs<BR>
simba-cs                 1543/udp  # simba-cs<BR>
aspeclmd                 1544/tcp  # aspeclmd<BR>
aspeclmd                 1544/udp  # aspeclmd<BR>
vistium-share            1545/tcp  # vistium-share<BR>
vistium-share            1545/udp  # vistium-share<BR>
abbaccuray               1546/tcp  # abbaccuray<BR>
abbaccuray               1546/udp  # abbaccuray<BR>
laplink                  1547/tcp  # laplink<BR>
laplink                  1547/udp  # laplink<BR>
axon-lm                  1548/tcp  # Axon License Manager<BR>
axon-lm                  1548/udp  # Axon License Manager<BR>
shivahose                1549/tcp  # Shiva Hose<BR>
shivasound               1549/udp  # Shiva Sound<BR>
3m-image-lm              1550/tcp  # Image Storage LM, 3M Inc<BR>
3m-image-lm              1550/udp  # Image Storage LM, 3M Inc<BR>
hecmtl-db                1551/tcp  # HECMTL-DB<BR>
hecmtl-db                1551/udp  # HECMTL-DB<BR>
pciarray                 1552/tcp  # pciarray<BR>
pciarray                 1552/udp  # pciarray<BR>
sna-cs                   1553/tcp  # sna-cs<BR>
sna-cs                   1553/udp  # sna-cs<BR>
caci-lm                  1554/tcp  # CACI Products Company LM<BR>
caci-lm                  1554/udp  # CACI Products Company LM<BR>
livelan                  1555/tcp  # livelan<BR>
livelan                  1555/udp  # livelan<BR>
ashwin                   1556/tcp  # AshWin CI Tecnologies<BR>
ashwin                   1556/udp  # AshWin CI Tecnologies<BR>
arbortext-lm             1557/tcp  # ArborText License Manager<BR>
arbortext-lm             1557/udp  # ArborText License Manager<BR>
xingmpeg                 1558/tcp  # xingmpeg<BR>
xingmpeg/streamworks/xing     1558/udp  # xingmpeg<BR>, StreamWorks<BR><br> Used for tx of high quality video (Xing) <BR> , Xing Stream Works<BR><br> Used for streaming video. <BR> 
web2host                 1559/tcp  # web2host<BR>
web2host                 1559/udp  # web2host<BR>
asci-val                 1560/tcp  # asci-val<BR>
asci-val                 1560/udp  # asci-val<BR>
facilityview             1561/tcp  # facilityview<BR>
facilityview             1561/udp  # facilityview<BR>
pconnectmgr              1562/tcp  # pconnectmgr<BR>
pconnectmgr              1562/udp  # pconnectmgr<BR>
cadabra-lm               1563/tcp  # Cadabra License Manager<BR>
cadabra-lm               1563/udp  # Cadabra License Manager<BR>
pay-per-view             1564/tcp  # Pay-Per-View<BR>
pay-per-view             1564/udp  # Pay-Per-View<BR>
winddlb                  1565/tcp  # WinDD<BR>
winddlb                  1565/udp  # WinDD<BR>
corelvideo               1566/tcp  # CORELVIDEO<BR>
corelvideo               1566/udp  # CORELVIDEO<BR>
jlicelmd                 1567/tcp  # jlicelmd<BR>
jlicelmd                 1567/udp  # jlicelmd<BR>
tsspmap                  1568/tcp  # tsspmap<BR>
tsspmap                  1568/udp  # tsspmap<BR>
ets                      1569/tcp  # ets<BR>
ets                      1569/udp  # ets<BR>
orbixd                   1570/tcp  # orbixd<BR>
orbixd                   1570/udp  # orbixd<BR>
rdb-dbs-disp             1571/tcp  # Oracle Remote Data Base<BR>
rdb-dbs-disp             1571/udp  # Oracle Remote Data Base<BR>
chip-lm                  1572/tcp  # Chipcom License Manager<BR>
chip-lm                  1572/udp  # Chipcom License Manager<BR>
itscomm-ns               1573/tcp  # itscomm-ns<BR>
itscomm-ns               1573/udp  # itscomm-ns<BR>
mvel-lm                  1574/tcp  # mvel-lm<BR>
mvel-lm                  1574/udp  # mvel-lm<BR>
oraclenames              1575/tcp  # oraclenames<BR>
oraclenames              1575/udp  # oraclenames<BR>
moldflow-lm              1576/tcp  # moldflow-lm<BR>
moldflow-lm              1576/udp  # moldflow-lm<BR>
hypercube-lm             1577/tcp  # hypercube-lm<BR>
hypercube-lm             1577/udp  # hypercube-lm<BR>
jacobus-lm               1578/tcp  # Jacobus License Manager<BR>
jacobus-lm               1578/udp  # Jacobus License Manager<BR>
ioc-sea-lm               1579/tcp  # ioc-sea-lm<BR>
ioc-sea-lm               1579/udp  # ioc-sea-lm<BR>
tn-tl-r1                 1580/tcp  # tn-tl-r1<BR>
tn-t1-r2/tn-tl-r2        1580/udp  # tc-t1-r2<BR>, tn-tl-r2<br><br>tn-tl-r2<br>
mil-2045-47001/vmf-msg-port     1581/tcp  # MIL-2045-47001<BR>, vmf-msg-port<BR>
mil-2045-47001/vmf-msg-port     1581/udp  # MIL-2045-47001<BR>, vmf-msg-port<BR>
msims                    1582/tcp  # MSIMS<BR>
msims                    1582/udp  # MSIMS<BR>
simbaexpress             1583/tcp  # simbaexpress<BR>
simbaexpress             1583/udp  # simbaexpress<BR>
tn-tl-fd2                1584/tcp  # tn-tl-fd2<BR>
tn-tl-fd2                1584/udp  # tn-tl-fd2<BR>
intv                     1585/tcp  # intv<BR>
intv                     1585/udp  # intv<BR>
ibm-abtact               1586/tcp  # ibm-abtact<BR>
ibm-abtact               1586/udp  # ibm-abtact<BR>
pra_elmd                 1587/tcp  # pra_elmd<BR>
pra_elmd                 1587/udp  # pra_elmd<BR>
triquest-lm              1588/tcp  # triquest-lm<BR>
triquest-lm              1588/udp  # triquest-lm<BR>
vqp                      1589/tcp  # VQP<BR>
vqp                      1589/udp  # VQP<BR>
gemini-lm                1590/tcp  # gemini-lm<BR>
gemini-lm                1590/udp  # gemini-lm<BR>
ncpm-pm                  1591/tcp  # ncpm-pm<BR>
ncpm-pm                  1591/udp  # ncpm-pm<BR>
commonspace              1592/tcp  # commonspace<BR>
commonspace              1592/udp  # commonspace<BR>
mainsoft-lm              1593/tcp  # mainsoft-lm<BR>
mainsoft-lm              1593/udp  # mainsoft-lm<BR>
sixtrak                  1594/tcp  # sixtrak<BR>
sixtrak                  1594/udp  # sixtrak<BR>
radio                    1595/tcp  # radio<BR>
radio                    1595/udp  # radio<BR>
radio-sm                 1596/tcp  # radio-sm<BR>
radio-bc                 1596/udp  # radio-bc<BR>
orbplus-iiop             1597/tcp  # orbplus-iiop<BR>
orbplus-iiop             1597/udp  # orbplus-iiop<BR>
picknfs                  1598/tcp  # picknfs<BR>
picknfs                  1598/udp  # picknfs<BR>
simbaservices            1599/tcp  # simbaservices<BR>
simbaservices            1599/udp  # simbaservices<BR>
issd                     1600/tcp  # issd<BR>
issd                     1600/udp  # issd<BR>
aas                      1601/tcp  # aas<BR>
aas                      1601/udp  # aas<BR>
inspect                  1602/tcp  # inspect<BR>
inspect                  1602/udp  # inspect<BR>
picodbc                  1603/tcp  # pickodbc<BR>
picodbc                  1603/udp  # pickodbc<BR>
icabrowser               1604/tcp  # icabrowser<BR>
icabrowser               1604/udp  # icabrowser<BR>
slp                      1605/tcp  # Salutation Mgr (Salutation Protocol)<BR>
slp                      1605/udp  # Salutation Mgr (Salutation Protocol)<BR>
slm-api                  1606/tcp  # Salutation Manager (SLM-API)<BR>
slm-api                  1606/udp  # Salutation Manager (SLM-API)<BR>
stt                      1607/tcp  # stt<BR>
stt                      1607/udp  # stt<BR>
smart-lm                 1608/tcp  # Smart Corp. License Manager<BR>
smart-lm                 1608/udp  # Smart Corp. License Manager<BR>
isysg-lm                 1609/tcp  # isysg-lm<BR>
isysg-lm                 1609/udp  # isysg-lm<BR>
taurus-wh                1610/tcp  # taurus-wh<BR>
taurus-wh                1610/udp  # taurus-wh<BR>
ill                      1611/tcp  # Inter Library Loan<BR>
ill                      1611/udp  # Inter Library Loan<BR>
netbill-trans            1612/tcp  # NetBill Transaction Server<BR>
netbill-trans            1612/udp  # NetBill Transaction Server<BR>
netbill-keyrep           1613/tcp  # NetBill Key Repository<BR>
netbill-keyrep           1613/udp  # NetBill Key Repository<BR>
netbill-cred             1614/tcp  # NetBill Credential Server<BR>
netbill-cred             1614/udp  # NetBill Credential Server<BR>
netbill-auth             1615/tcp  # NetBill Authorization Server<BR>
netbill-auth             1615/udp  # NetBill Authorization Server<BR>
netbill-prod             1616/tcp  # NetBill Product Server<BR>
netbill-prod             1616/udp  # NetBill Product Server<BR>
nimrod-agent             1617/tcp  # Nimrod Inter-Agent Communication<BR>
nimrod-agent             1617/udp  # Nimrod Inter-Agent Communication<BR>
skytelnet                1618/tcp  # skytelnet<BR>
skytelnet                1618/udp  # skytelnet<BR>
xs-openstorage           1619/tcp  # xs-openstorage<BR>
xs-openstorage           1619/udp  # xs-openstorage<BR>
faxportwinport           1620/tcp  # Faxportwinport<BR>
faxportwinport           1620/udp  # Faxportwinport<BR>
softdataphone            1621/tcp  # Softdataphone<BR>
softdataphone            1621/udp  # Softdataphone<BR>
ontime                   1622/tcp  # OnTime Calendar Services<BR>
ontime                   1622/udp  # OnTime Calendar Services<BR>
jaleosnd                 1623/tcp  # jaleosnd<BR>
jaleosnd                 1623/udp  # jaleosnd<BR>
udp-sr-port              1624/tcp  # udp-sr-port<BR>
udp-sr-port              1624/udp  # udp-sr-port<BR>
svs-omagent              1625/tcp  # svs-omagent<BR>
svs-omagent              1625/udp  # svs-omagent<BR>
shockwave                1626/tcp  # Shockwave<BR>
shockwave                1626/udp  # Shockwave<BR>
t128-gateway             1627/tcp  # T.128 Gateway<BR>
t128-gateway             1627/udp  # T.128 Gateway<BR>
longtalk-norm/lontalk-norm     1628/tcp  # LongTalk normal<BR>, lontalk-norm<br><br>lontalk normal<br>
longtalk-norm/lontalk-norm     1628/udp  # LongTalk normal<BR>, lontalk-norm<br><br>lontalk normal<br>
longtalk-urgnt/lontalk-urgnt     1629/tcp  # LongTalk urgent<BR>, lontalk-urgnt<br><br>lontalk urgent<br>
longtalk-urgnt/lontalk-urgnt     1629/udp  # LongTalk urgent<BR>, lontalk-urgnt<br><br>lontalk urgent<br>
oraclenet8cman           1630/tcp  # Oracle Net8 Cman<BR>
oraclenet8cman           1630/udp  # Oracle Net8 Cman<BR>
visitview                1631/tcp  # Visit View<BR>
visitview                1631/udp  # Visit View<BR>
pammratc                 1632/tcp  # PAMMRATC<BR>
pammratc                 1632/udp  # PAMMRATC<BR>
pammrpc                  1633/tcp  # PAMMRPC<BR>
pammrpc                  1633/udp  # PAMMRPC<BR>
loaprobe                 1634/tcp  # EDB Server 1<BR>
loaprobe                 1634/udp  # EDB Server 1<BR>
edb-server1              1635/tcp  # EDB Server 1<BR>
edb-server1              1635/udp  # EDB Server 1<BR>
cncp                     1636/tcp  # CableNet Control Protocol<BR>
cncp                     1636/udp  # CableNet Control Protocol<BR>
cnap                     1637/tcp  # CableNet Admin Protocol<BR>
cnap                     1637/udp  # CableNet Admin Protocol<BR>
cnip                     1638/tcp  # CableNet Info Protocol<BR>
cnip                     1638/udp  # CableNet Info Protocol<BR>
cert-initiator           1639/tcp  # cert-initiator<BR>
cert-initiator           1639/udp  # cert-initiator<BR>
cert-responder           1640/tcp  # cert-responder<BR>
cert-responder           1640/udp  # cert-responder<BR>
invision                 1641/tcp  # InVision<BR>
invision                 1641/udp  # InVision<BR>
isis-am                  1642/tcp  # isis-am<BR>
isis-am                  1642/udp  # isis-am<BR>
isis-ambc                1643/tcp  # isis-ambc<BR>
isis-ambc                1643/udp  # isis-ambc<BR>
saiseh/saiseh            1644/tcp  # Satellite-Data Acquisition System 4<BR>, saiseh<br><br>satellite-data acquisition system 4<br>
saiseh                   1644/udp  # Satellite-Data Acquisition System 4<BR>
datametrics/radius       1645/tcp  # datametrics<BR>, Radius Authentication Services<BR>
datametrics/radius/datametrics     1645/udp  # datametrics<BR>, Radius Authentication Services<BR>, datametrics<br><br>radius authentication, datametrics<br>
sa-msg-port              1646/tcp  # sa-msg-port<BR>
sa-msg-port/sa-msg-port     1646/udp  # sa-msg-port<BR>, sa-msg-port<br><br>sa-msg-port, radius accounting<br>
rsap                     1647/tcp  # rsap<BR>
rsap                     1647/udp  # rsap<BR>
concurrent-lm            1648/tcp  # concurrent-lm<BR>
concurrent-lm            1648/udp  # concurrent-lm<BR>
inspect/kermit           1649/tcp  # inspect<BR>, kermit<BR>
inspect/kermit           1649/udp  # inspect<BR>, kermit<BR>
nkd                      1650/tcp  # nkd<BR>
nkd                      1650/udp  # nkd<BR>
shiva_confsrvr           1651/tcp  # shiva_confsrvr<BR>
shiva_confsrvr           1651/udp  # shiva_confsrvr<BR>
xnmp                     1652/tcp  # xnmp<BR>
xnmp                     1652/udp  # xnmp<BR>
alphatech-lm             1653/tcp  # alphatech-lm<BR>
alphatech-lm             1653/udp  # alphatech-lm<BR>
stargatealerts           1654/tcp  # stargatealerts<BR>
stargatealerts           1654/udp  # stargatealerts<BR>
dec-mbadmin              1655/tcp  # dec-mbadmin<BR>
dec-mbadmin              1655/udp  # dec-mbadmin<BR>
dec-mbadmin-h            1656/tcp  # dec-mbadmin-h<BR>
dec-mbadmin-h            1656/udp  # dec-mbadmin-h<BR>
fujitsu-mmpdc            1657/tcp  # fujitsu-mmpdc<BR>
fujitsu-mmpdc            1657/udp  # fujitsu-mmpdc<BR>
sixnetudr                1658/tcp  # sixnetudr<BR>
sixnetudr                1658/udp  # sixnetudr<BR>
sg-lm                    1659/tcp  # Silicon Grail License Manager<BR>
sg-lm                    1659/udp  # Silicon Grail License Manager<BR>
skip-mc-gikreq           1660/tcp  # skip-mc-gikreq<BR>
skip-mc-gikreq           1660/udp  # skip-mc-gikreq<BR>
netview-aix-1            1661/tcp  # netview-aix-1<BR>
netview-aix-1            1661/udp  # netview-aix-1<BR>
netview-aix-2            1662/tcp  # netview-aix-2<BR>
netview-aix-2            1662/udp  # netview-aix-2<BR>
netview-aix-3            1663/tcp  # netview-aix-3<BR>
netview-aix-3            1663/udp  # netview-aix-3<BR>
netview-aix-4            1664/tcp  # netview-aix-4<BR>
netview-aix-4            1664/udp  # netview-aix-4<BR>
netview-aix-5            1665/tcp  # netview-aix-5<BR>
netview-aix-5            1665/udp  # netview-aix-5<BR>
netview-aix-6            1666/tcp  # netview-aix-6<BR>
maze/netview-aix-6       1666/udp  # maze<BR>, netview-aix-6<BR>
netview-aix-7            1667/tcp  # netview-aix-7<BR>
netview-aix-7            1667/udp  # netview-aix-7<BR>
netview-aix-8            1668/tcp  # netview-aix-8<BR>
netview-aix-8            1668/udp  # netview-aix-8<BR>
netview-aix-9            1669/tcp  # netview-aix-9<BR>
netview-aix-9            1669/udp  # netview-aix-9<BR>
netview-aix-10           1670/tcp  # netview-aix-10<BR>
netview-aix-10           1670/udp  # netview-aix-10<BR>
netview-aix-11           1671/tcp  # netview-aix-11<BR>
netview-aix-11           1671/udp  # netview-aix-11<BR>
netview-aix-12           1672/tcp  # netview-aix-12<BR>
netview-aix-12           1672/udp  # netview-aix-12<BR>
proshare-mc-1            1673/tcp  # Intel Proshare Multicast<BR>
proshare-mc-1            1673/udp  # Intel Proshare Multicast<BR>
proshare-mc-2            1674/tcp  # Intel Proshare Multicast<BR>
proshare-mc-2            1674/udp  # Intel Proshare Multicast<BR>
pdp                      1675/tcp  # Pacific Data Products<BR>
pdp                      1675/udp  # Pacific Data Products<BR>
netcomm1                 1676/tcp  # netcomm1<BR>
netcomm1/netcomm2        1676/udp  # netcomm1<BR>, netcomm2<br><br>netcomm2<br>
groupwise                1677/tcp  # groupwise<BR>
groupwise                1677/udp  # groupwise<BR>
prolink                  1678/tcp  # prolink<BR>
prolink                  1678/udp  # prolink<BR>
darcorp-lm               1679/tcp  # darcorp-lm<BR>
darcorp-lm               1679/udp  # darcorp-lm<BR>
microcom-sbp             1680/tcp  # microcom-sbp<BR>
microcom-sbp             1680/udp  # microcom-sbp<BR>
sd-elmd                  1681/tcp  # sd-elmd<BR>
sd-elmd                  1681/udp  # sd-elmd<BR>
lanyon-lantern           1682/tcp  # lanyon-lantern<BR>
lanyon-lantern           1682/udp  # lanyon-lantern<BR>
ncpm-hip                 1683/tcp  # ncpm-hip<BR>
ncpm-hip                 1683/udp  # ncpm-hip<BR>
snaresecure              1684/tcp  # SnareSecure<BR>
snaresecure              1684/udp  # SnareSecure<BR>
n2nremote                1685/tcp  # n2nremote<BR>
n2nremote                1685/udp  # n2nremote<BR>
cvmon                    1686/tcp  # cvmon<BR>
cvmon                    1686/udp  # cvmon<BR>
nsjtp-ctrl               1687/tcp  # nsjtp-ctrl<BR>
nsjtp-ctrl               1687/udp  # nsjtp-ctrl<BR>
nsjtp-data               1688/tcp  # nsjtp-data<BR>
nsjtp-data               1688/udp  # nsjtp-data<BR>
firefox                  1689/tcp  # firefox<BR>
firefox                  1689/udp  # firefox<BR>
ng-umds                  1690/tcp  # ng-umds<BR>
ng-umds                  1690/udp  # ng-umds<BR>
empire-empuma            1691/tcp  # empire-empuma<BR>
empire-empuma            1691/udp  # empire-empuma<BR>
sstsys-lm                1692/tcp  # sstsys-lm<BR>
sstsys-lm                1692/udp  # sstsys-lm<BR>
rrirtr                   1693/tcp  # rrirtr<BR>
rrirtr                   1693/udp  # rrirtr<BR>
rrimwm                   1694/tcp  # rrimwm<BR>
rrimwm                   1694/udp  # rrimwm<BR>
rrilwm                   1695/tcp  # rrilwm<BR>
rrilwm                   1695/udp  # rrilwm<BR>
rrifmm                   1696/tcp  # rrifmm<BR>
rrifmm                   1696/udp  # rrifmm<BR>
rrisat                   1697/tcp  # rrisat<BR>
rrisat                   1697/udp  # rrisat<BR>
rsvp-encap-1             1698/tcp  # RSVP-ENCAPSULATION-1<BR>
rsvp-encap-1             1698/udp  # RSVP-ENCAPSULATION-1<BR>
rsvp-encap-2             1699/tcp  # RSVP-ENCAPSULATION-2<BR>
rsvp-encap-2             1699/udp  # RSVP-ENCAPSULATION-2<BR>
mps-raft                 1700/tcp  # mps-raft<BR>
mps-raft                 1700/udp  # mps-raft<BR>
l2f/l2tp                 1701/tcp  # l2f<BR>, Layer Two Tunneling Protocol (L2TP)<BR> <br> L2TP is MS's VPN protocol, replacing PPTP.<BR>
l2f/l2tp/ipsec           1701/udp  # l2f<BR>, Layer Two Tunneling Protocol (L2TP)<BR> <br> L2TP is MS's VPN protocol, replacing PPTP.<BR>, IPSEC Setup<BR><br> VPN negotiation port for IPSEC setup (eg: MS's L2TP VPN). <BR> 
deskshare                1702/tcp  # Deskshare<BR>
deskshare                1702/udp  # Deskshare<BR>
hb-engine                1703/tcp  # HB Engine<BR>
hb-engine                1703/udp  # HB Engine<BR>
bcs-broker               1704/tcp  # BCS Broker<BR>
bcs-broker               1704/udp  # BCS Broker<BR>
slingshot                1705/tcp  # Slingshot<BR>
slingshot                1705/udp  # Slingshot<BR>
jetform                  1706/tcp  # Jetform<BR>
jetform                  1706/udp  # Jetform<BR>
vdmplay                  1707/tcp  # VDMPlay<BR>
vdmplay                  1707/udp  # VDMPlay<BR>
gat-lmd                  1708/tcp  # gat-lmd<BR>
gat-lmd                  1708/udp  # gat-lmd<BR>
centra                   1709/tcp  # Centra<BR>
centra                   1709/udp  # Centra<BR>
impera                   1710/tcp  # Impera<BR>
impera                   1710/udp  # Impera<BR>
pptconference            1711/tcp  # PPT Conference<BR>
pptconference            1711/udp  # PPT Conference<BR>
registrar                1712/tcp  # Resource Monitoring Service<BR>
registrar                1712/udp  # Resource Monitoring Service<BR>
conferencetalk           1713/tcp  # ConferenceTalk<BR>
conferencetalk           1713/udp  # ConferenceTalk<BR>
sesi-lm                  1714/tcp  # SESI License Manager<BR>
sesi-lm                  1714/udp  # SESI License Manager<BR>
houdini-lm               1715/tcp  # Houdini License Manager<BR>
houdini-lm               1715/udp  # Houdini License Manager<BR>
xmsg                     1716/tcp  # XMSG<BR>
xmsg                     1716/udp  # XMSG<BR>
fj-hdnet                 1717/tcp  # fj-hdnet<BR>
convoy/fj-hdnet          1717/udp  # Convoy Clustering (WLBS)<br> Used in NT/Win2000 clustering.<BR> , fj-hdnet<BR>
h323gatedisc             1718/tcp  # H.323 Gatedisc<BR>
h323gatedisc             1718/udp  # H.323 Gatedisc<BR>
h323gatestat             1719/tcp  # H.323 Gatestat<BR>
h323gatestat             1719/udp  # H.323 Gatestat<BR>
h323hostcall/livelan     1720/tcp  # H.323 Hostcall<BR><br> H.323 call setup protocol used by multimedia collaborative apps such as NetMeeting to establish and control a collaborative session. Session data transfer will use H.323 udp streaming (AKA: RealTime Protocol [RTP]). <BR> , LiveLan (H.323 compliant)<BR>
h323hostcall             1720/udp  # H.323 Hostcall<BR><br> H.323 call setup protocol used by multimedia collaborative apps such as NetMeeting to establish and control a collaborative session. Session data transfer will use H.323 udp streaming (AKA: RealTime Protocol [RTP]). <BR> 
caicci                   1721/tcp  # caicci<BR>
caicci                   1721/udp  # caicci<BR>
hks-lm                   1722/tcp  # HKS License Manager<BR>
hks-lm                   1722/udp  # HKS License Manager<BR>
pptpc                    1723/tcp  # PPTP Control Channel<BR><br> NT's Point-to-Point-Tunneling Protocol, used for VPNs. Noted to be weak, due to non-changing random seed for RC4 streaming algorithm (used user's password for random seed, which does not change for each session). Captured streams could be xor'd against each other to recover the seed (user password). MS has replaced it with L2TP using tcp 1701. <BR> 
pptpc/pptp               1723/udp  # PPTP Control Channel<BR><br> NT's Point-to-Point-Tunneling Protocol, used for VPNs. Noted to be weak, due to non-changing random seed for RC4 streaming algorithm (used user's password for random seed, which does not change for each session). Captured streams could be xor'd against each other to recover the seed (user password). MS has replaced it with L2TP using tcp 1701. <BR> , pptp<br><br>pptp<br>
csbphonemaster           1724/tcp  # csbphonemaster<BR>
csbphonemaster           1724/udp  # csbphonemaster<BR>
iden-ralp/pptp           1725/tcp  # iden-ralp<BR>, PPTP Data Port<BR><br> See comments on pptpc (1723) <BR> 
iden-ralp                1725/udp  # iden-ralp<BR>
iberiagames              1726/tcp  # IBERIAGAMES<BR>
iberiagames              1726/udp  # IBERIAGAMES<BR>
winddx                   1727/tcp  # winddx<BR>
winddx                   1727/udp  # winddx<BR>
telindus                 1728/tcp  # TELINDUS<BR>
telindus                 1728/udp  # TELINDUS<BR>
citynl                   1729/tcp  # CityNL License Management<BR>
citynl                   1729/udp  # CityNL License Management<BR>
roketz                   1730/tcp  # roketz<BR>
roketz                   1730/udp  # roketz<BR>
msiccp                   1731/tcp  # MS ICCP (Audio Call Control Protocol)<BR><br> Used to establish and maintain datastream sessions for multimedia collaborative apps such as NetMeeting. Concern is in its random-high selection for datastream udp ports for each session, complicating packet filtering decisions. <BR> 
msiccp                   1731/udp  # MS ICCP (Audio Call Control Protocol)<BR><br> Used to establish and maintain datastream sessions for multimedia collaborative apps such as NetMeeting. Concern is in its random-high selection for datastream udp ports for each session, complicating packet filtering decisions. <BR> 
proxim                   1732/tcp  # proxim<BR>
proxim                   1732/udp  # proxim<BR>
siipat                   1733/tcp  # SIMS - SIIPAT Protocol for Alarms<BR>
siipat                   1733/udp  # SIMS - SIIPAT Protocol for Alarms<BR>
cambertx-lm              1734/tcp  # Camber Corporation License Manager<BR>
cambertx-lm              1734/udp  # Camber Corporation License Manager<BR>
privatechat              1735/tcp  # PrivateChat<BR>
privatechat              1735/udp  # PrivateChat<BR>
street-stream            1736/tcp  # Street-Stream<BR>
street-stream            1736/udp  # Street-Stream<BR>
ultimad                  1737/tcp  # UltiMad<BR>
ultimad                  1737/udp  # UltiMad<BR>
gamegen1                 1738/tcp  # GameGen1<BR>
gamegen1                 1738/udp  # GameGen1<BR>
webaccess                1739/tcp  # webaccess<BR>
webaccess                1739/udp  # webaccess<BR>
encore                   1740/tcp  # Encore<BR>
encore                   1740/udp  # Encore<BR>
cisco-net-mgmt           1741/tcp  # Cisco Network Mgmt<BR>
cisco-net-mgmt           1741/udp  # Cisco Network Mgmt<BR>
3Com-nsd                 1742/tcp  # 3Com-nsd<BR>
3Com-nsd                 1742/udp  # 3Com-nsd<BR>
cinegrfx-lm              1743/tcp  # Cinema Graphics License Manager<BR>
cinegrfx-lm              1743/udp  # Cinema Graphics License Manager<BR>
ncpm-ft                  1744/tcp  # ncpm-ft<BR>
ncpm-ft                  1744/udp  # ncpm-ft<BR>
remote-winsock           1745/tcp  # Remote-WINSOCK<BR><br> Used as a Winsock control channel between internal clients and site proxy. Example is MS-Proxy, where it establishes Winsock client and proxy connection, exchanges LAT info, etc. <BR> 
remote-winsock           1745/udp  # Remote-WINSOCK<BR><br> Used as a Winsock control channel between internal clients and site proxy. Example is MS-Proxy, where it establishes Winsock client and proxy connection, exchanges LAT info, etc. <BR> 
ftrapid-1                1746/tcp  # ftrapid-1<BR>
ftrapid-1                1746/udp  # ftrapid-1<BR>
ftrapid-2                1747/tcp  # ftrapid-2<BR>
ftrapid-2                1747/udp  # ftrapid-2<BR>
oracle-em1               1748/tcp  # oracle-em1<BR>
oracle-em1               1748/udp  # oracle-em1<BR>
aspen-services           1749/tcp  # aspen-services<BR>
aspen-services           1749/udp  # aspen-services<BR>
sslp                     1750/tcp  # Simple Socket Library's PortMaster<BR>
sslp                     1750/udp  # Simple Socket Library's PortMaster<BR>
swiftnet                 1751/tcp  # SwiftNet<BR>
swiftnet                 1751/udp  # SwiftNet<BR>
lofr-lm                  1752/tcp  # Leap of Faith Research License Manager<BR>
lofr-lm                  1752/udp  # Leap of Faith Research License Manager<BR>
translogic-lm            1753/tcp  # Translogic License Manager<BR>
translogic-lm            1753/udp  # Translogic License Manager<BR>
oracle-em2               1754/tcp  # oracle-em2<BR>
oracle-em2               1754/udp  # oracle-em2<BR>
ms-streaming             1755/tcp  # Microsoft NetShow Command Port<BR><br> Server control port. Two conflicting reports on port server sets up as data stream back to client: <BR> - On udp 1755 to the client <BR> - On random udp between 1024-5000 <BR> 
ms-streaming             1755/udp  # Microsoft NetShow Command Port<BR><br> Server control port. Two conflicting reports on port server sets up as data stream back to client: <BR> - On udp 1755 to the client <BR> - On random udp between 1024-5000 <BR> 
capfast-lmd              1756/tcp  # capfast-lmd<BR>
capfast-lmd              1756/udp  # capfast-lmd<BR>
cnhrp                    1757/tcp  # cnhrp<BR>
cnhrp                    1757/udp  # cnhrp<BR>
tftp-mcast               1758/tcp  # tftp-mcast<BR>
tftp-mcast               1758/udp  # tftp-mcast<BR>
spss-lm                  1759/tcp  # SPSS License Manager<BR>
spss-lm                  1759/udp  # SPSS License Manager<BR>
www-ldap-gw              1760/tcp  # www-ldap-gw<BR>
www-ldap-gw              1760/udp  # www-ldap-gw<BR>
cft-0                    1761/tcp  # cft-0<BR>
cft-0                    1761/udp  # cft-0<BR>
cft-1                    1762/tcp  # cft-1<BR>
cft-1                    1762/udp  # cft-1<BR>
cft-2                    1763/tcp  # cft-2<BR>
cft-2                    1763/udp  # cft-2<BR>
cft-3                    1764/tcp  # cft-3<BR>
cft-3                    1764/udp  # cft-3<BR>
cft-4                    1765/tcp  # cft-4<BR>
cft-4                    1765/udp  # cft-4<BR>
cft-5                    1766/tcp  # cft-5<BR>
cft-5                    1766/udp  # cft-5<BR>
cft-6                    1767/tcp  # cft-6<BR>
cft-6                    1767/udp  # cft-6<BR>
cft-7                    1768/tcp  # cft-7<BR>
cft-7                    1768/udp  # cft-7<BR>
bmc-net-adm              1769/tcp  # bmc-net-adm<BR>
bmc-net-adm              1769/udp  # bmc-net-adm<BR>
bmc-net-svc              1770/tcp  # bmc-net-svc<BR>
bmc-net-svc              1770/udp  # bmc-net-svc<BR>
vaultbase                1771/tcp  # vaultbase<BR>
vaultbase                1771/udp  # vaultbase<BR>
essweb-gw                1772/tcp  # EssWeb Gateway<BR>
essweb-gw                1772/udp  # EssWeb Gateway<BR>
kmscontrol               1773/tcp  # KMSControl<BR>
kmscontrol               1773/udp  # KMSControl<BR>
global-dtserv            1774/tcp  # global-dtserv<BR>
global-dtserv            1774/udp  # global-dtserv<BR>
femis                    1776/tcp  # Fed Emergency Mgmt Info System<BR>
femis                    1776/udp  # Fed Emergency Mgmt Info System<BR>
powerguardian            1777/tcp  # PowerGuardian<BR>
powerguardian            1777/udp  # PowerGuardian<BR>
prodigy-internet/prodigy-intrnet     1778/tcp  # prodigy-internet<BR>, prodigy-intrnet<br><br>prodigy-internet<br>
prodigy-internet/prodigy-intrnet     1778/udp  # prodigy-internet<BR>, prodigy-intrnet<br><br>prodigy-internet<br>
pharmasoft               1779/tcp  # pharmasoft<BR>
pharmasoft               1779/udp  # pharmasoft<BR>
dpkeyserv                1780/tcp  # DP Key Server<BR>
dpkeyserv                1780/udp  # DP Key Server<BR>
answersoft-lm            1781/tcp  # AnswerSoft License Manager<BR>
answersoft-lm            1781/udp  # AnswerSoft License Manager<BR>
hp-hcip                  1782/tcp  # hp-hcip<BR>
hp-hcip                  1782/udp  # hp-hcip<BR>
fjris                    1783/tcp  # Fujitsu Remote Install Service<BR>
fjris                    1783/udp  # Fujitsu Remote Install Service<BR>
finle-lm                 1784/tcp  # Finle License Manager<BR>
finle-lm                 1784/udp  # Finle License Manager<BR>
windlm                   1785/tcp  # Wind River Systems License Manager<BR>
windlm                   1785/udp  # Wind River Systems License Manager<BR>
funk-logger              1786/tcp  # funk-logger<BR>
funk-logger              1786/udp  # funk-logger<BR>
funk-license             1787/tcp  # funk-license<BR>
funk-license             1787/udp  # funk-license<BR>
psmond                   1788/tcp  # psmond<BR>
psmond                   1788/udp  # psmond<BR>
hello                    1789/tcp  # hello<BR>
hello                    1789/udp  # hello<BR>
nmsp                     1790/tcp  # Narrative Media Streaming Protocol<BR>
nmsp                     1790/udp  # Narrative Media Streaming Protocol<BR>
ea1                      1791/tcp  # EA1<BR>
ea1                      1791/udp  # EA1<BR>
ibm-dt-2                 1792/tcp  # ibm-dt-2<BR>
ibm-dt-2                 1792/udp  # ibm-dt-2<BR>
rsc-robot                1793/tcp  # rsc-robot<BR>
rsc-robot                1793/udp  # rsc-robot<BR>
cera-bcm                 1794/tcp  # cera-bcm<BR>
cera-bcm                 1794/udp  # cera-bcm<BR>
dpi-proxy                1795/tcp  # dpi-proxy<BR>
dpi-proxy                1795/udp  # dpi-proxy<BR>
vocaltec-admin           1796/tcp  # Vocaltec Server Administration<BR>
vocaltec-admin           1796/udp  # Vocaltec Server Administration<BR>
uma                      1797/tcp  # UMA<BR>
uma                      1797/udp  # UMA<BR>
etp                      1798/tcp  # Event Transfer Protocol<BR>
etp                      1798/udp  # Event Transfer Protocol<BR>
netrisk                  1799/tcp  # NETRISK<BR>
netrisk                  1799/udp  # NETRISK<BR>
ansys-lm                 1800/tcp  # ANSYS-License manager<BR>
ansys-lm                 1800/udp  # ANSYS-License manager<BR>
msmq                     1801/tcp  # Microsoft Message Que<BR>
msmq                     1801/udp  # Microsoft Message Que<BR>
concomp1                 1802/tcp  # ConComp1<BR>
concomp1                 1802/udp  # ConComp1<BR>
hp-hcip-gwy              1803/tcp  # HP-HCIP-GWY<BR>
hp-hcip-gwy              1803/udp  # HP-HCIP-GWY<BR>
enl                      1804/tcp  # ENL<BR>
enl                      1804/udp  # ENL<BR>
enl-name                 1805/tcp  # ENL-Name<BR>
enl-name                 1805/udp  # ENL-Name<BR>
musiconline              1806/tcp  # Musiconline<BR>
musiconline              1806/udp  # Musiconline<BR>
fhsp                     1807/tcp  # Fujitsu Hot Standby Protocol<BR>
fhsp                     1807/udp  # Fujitsu Hot Standby Protocol<BR>
oracle-vp2               1808/tcp  # Oracle-VP2<BR>
oracle-vp2               1808/udp  # Oracle-VP2<BR>
oracle-vp1               1809/tcp  # Oracle-VP1<BR>
oracle-vp1               1809/udp  # Oracle-VP1<BR>
jerand-lm                1810/tcp  # Jerand License Manager<BR>
jerand-lm                1810/udp  # Jerand License Manager<BR>
scientia-sdb             1811/tcp  # Scientia-SDB<BR>
scientia-sdb             1811/udp  # Scientia-SDB<BR>
radius                   1812/tcp  # RADIUS<BR>
radius/radius            1812/udp  # RADIUS<BR>, radius<br><br>radius, radius authentication protocol (iana sanctioned), radius authentication protocol (rfc 2138)<br>
radius-acct              1813/tcp  # RADIUS Accounting<BR>
radius-acct/radius-acct     1813/udp  # RADIUS Accounting<BR>, radius-acct<br><br>radius accounting protocol (rfc 2139), radius accounting, radius accounting protocol (iana sanctioned)<br>
tdp-suite                1814/tcp  # TDP Suite<BR>
tdp-suite                1814/udp  # TDP Suite<BR>
mmpft                    1815/tcp  # MMPFT<BR>
mmpft                    1815/udp  # MMPFT<BR>
harp                     1816/tcp  # HARP<BR>
harp                     1816/udp  # HARP<BR>
rkb-oscs                 1817/tcp  # RKB-OSCS<BR>
rkb-oscs                 1817/udp  # RKB-OSCS<BR>
etftp                    1818/tcp  # Enhanced TFTP<BR>
etftp                    1818/udp  # Enhanced TFTP<BR>
plato-lm                 1819/tcp  # Plato License Manager<BR>
plato-lm                 1819/udp  # Plato License Manager<BR>
mcagent                  1820/tcp  # MC Agent<BR>
mcagent                  1820/udp  # MC Agent<BR>
donnyworld               1821/tcp  # DonnyWorld<BR>
donnyworld               1821/udp  # DonnyWorld<BR>
es-elmd                  1822/tcp  # es-elmd<BR>
es-elmd                  1822/udp  # es-elmd<BR>
unisys-lm                1823/tcp  # Unisys Natural Language LM<BR>
unisys-lm                1823/udp  # Unisys Natural Language LM<BR>
metrics-pas              1824/tcp  # metrics-pas<BR>
metrics-pas              1824/udp  # metrics-pas<BR>
direcpc-video/ardusmu1     1825/tcp  # DirecPC Video<BR>, ARDUS Multicast<BR>
direcpc-video/ardusmu1     1825/udp  # DirecPC Video<BR>, ARDUS Multicast<BR>
ardt                     1826/tcp  # ARDT<BR>
ardt                     1826/udp  # ARDT<BR>
asi                      1827/tcp  # ASI<BR>
asi/asi                  1827/udp  # ASI<BR>, asi<br><br>asi<br>
itm-mcell-u              1828/tcp  # itm-mcell-u<BR>
itm-mcell-u              1828/udp  # itm-mcell-u<BR>
optika-emedia            1829/tcp  # Opika eMedia<BR>
optika-emedia            1829/udp  # Opika eMedia<BR>
net8-cman                1830/tcp  # Oracle Net8 Cman Admin<BR>
net8-cman                1830/udp  # Oracle Net8 Cman Admin<BR>
myrtle                   1831/tcp  # Myrtle<BR>
myrtle                   1831/udp  # Myrtle<BR>
tht-treasure             1832/tcp  # ThoughtTreasure<BR>
tht-treasure             1832/udp  # ThoughtTreasure<BR>
udpradio                 1833/tcp  # udpradio<br><br>udpradio<br>
udpradio/udpradio        1833/udp  # UDP Radio<BR>, udpradio<br><br>udpradio<br>
ardusuni                 1834/tcp  # ARDUS Unicast<BR>
ardusuni                 1834/udp  # ARDUS Unicast<BR>
ste-smsc                 1836/tcp  # ste-smsc<BR>
ste-smsc                 1836/udp  # ste-smsc<BR>
csoft1                   1837/tcp  # csoft1<BR>
csoft1                   1837/udp  # csoft1<BR>
talnet                   1838/tcp  # TALNET<BR>
talnet                   1838/udp  # TALNET<BR>
netopia-vo1              1839/tcp  # netopia-vo1<BR>
netopia-vo1              1839/udp  # netopia-vo1<BR>
netopia-vo2              1840/tcp  # netopia-vo2<BR>
netopia-vo2              1840/udp  # netopia-vo2<BR>
netopia-vo3              1841/tcp  # netopia-vo3<BR>
netopia-vo3              1841/udp  # netopia-vo3<BR>
netopia-vo4              1842/tcp  # netopia-vo4<BR>
netopia-vo4              1842/udp  # netopia-vo4<BR>
netopia-vo5              1843/tcp  # netopia-vo5<BR>
netopia-vo5              1843/udp  # netopia-vo5<BR>
direcpc-dll              1844/tcp  # DirectPC-DLL<BR>
direcpc-dll              1844/udp  # DirectPC-DLL<BR>
gsi                      1850/tcp  # GSI<BR>
gsi                      1850/udp  # GSI<BR>
ctcd                     1851/tcp  # ctcd<BR>
ctcd                     1851/udp  # ctcd<BR>
sunscalar-svc            1860/tcp  # SunSCALAR Services<BR>
sunscalar-svc            1860/udp  # SunSCALAR Services<BR>
lecroy-vicp              1861/tcp  # LeCroy VICP<BR>
lecroy-vicp              1861/udp  # LeCroy VICP<BR>
techra-server            1862/tcp  # Techra Server<BR>
techra-server            1862/udp  # Techra Server<BR>
msnp                     1863/tcp  # MSNP<BR>
msnp                     1863/udp  # MSNP<BR>
paradym-31port           1864/tcp  # Paradym 31 Port<BR>
paradym-31port           1864/udp  # Paradym 31 Port<BR>
entp                     1865/tcp  # ENTP<BR>
entp                     1865/udp  # ENTP<BR>
sunscalar-dns            1870/tcp  # SunSCALAR DNS Service<BR>
sunscalar-dns            1870/udp  # SunSCALAR DNS Service<BR>
canocentral0             1871/tcp  # Cano Central 0<BR>
canocentral0             1871/udp  # Cano Central 0<BR>
canocentral1             1872/tcp  # Cano Central 1<BR>
canocentral1             1872/udp  # Cano Central 1<BR>
fjmpjps                  1873/tcp  # fjmpjps<BR>
fjmpjps                  1873/udp  # fjmpjps<BR>
fjswapsnp                1874/tcp  # fjswapsnp<BR>
fjswapsnp                1874/udp  # fjswapsnp<BR>
ibm-mqseries2            1881/tcp  # IBM MQSeries<BR>
ibm-mqseries2            1881/udp  # IBM MQSeries<BR>
vista-4gl                1895/tcp  # Vista 4GL<BR>
vista-4gl                1895/udp  # Vista 4GL<BR>
mc2studios               1896/tcp  # MC2Studios<BR>
mc2studios               1896/udp  # MC2Studios<BR>
ssdp                     1900/tcp  # SSDP<BR>
ssdp                     1900/udp  # SSDP<BR>
fjicl-tep-a              1901/tcp  # Fujitsu ICL Terminal Emulator Program A<BR>
fjicl-tep-a              1901/udp  # Fujitsu ICL Terminal Emulator Program A<BR>
fjicl-tep-b              1902/tcp  # Fujitsu ICL Terminal Emulator Program B<BR>
fjicl-tep-b              1902/udp  # Fujitsu ICL Terminal Emulator Program B<BR>
linkname                 1903/tcp  # Local Link Name Resolution<BR>
linkname                 1903/udp  # Local Link Name Resolution<BR>
fjicl-tep-c              1904/tcp  # Fujitsu ICL Terminal Emulator Program C<BR>
fjicl-tep-c              1904/udp  # Fujitsu ICL Terminal Emulator Program C<BR>
sugp                     1905/tcp  # Secure UP.Link Gateway Protocol<BR>
sugp                     1905/udp  # Secure UP.Link Gateway Protocol<BR>
tpmd                     1906/tcp  # TPortMapperReq<BR>
tpmd                     1906/udp  # TPortMapperReq<BR>
intrastar                1907/tcp  # IntraSTAR<BR>
intrastar                1907/udp  # IntraSTAR<BR>
dawn                     1908/tcp  # Dawn<BR>
dawn                     1908/udp  # Dawn<BR>
global-wlink             1909/tcp  # Global World Link<BR>
global-wlink             1909/udp  # Global World Link<BR>
ultrabac                 1910/tcp  # ultrabac<BR>
ultrabac                 1910/udp  # ultrabac<BR>
mtp                      1911/tcp  # Starlight Net Multimedia Tx Protocol<BR>
mtp                      1911/udp  # Starlight Net Multimedia Tx Protocol<BR>
rhp-iibp                 1912/tcp  # rhp-iibp<BR>
rhp-iibp                 1912/udp  # rhp-iibp<BR>
armadp                   1913/tcp  # Armadp<BR>
armadp                   1913/udp  # Armadp<BR>
elm-momentum             1914/tcp  # Elm-Momentum<BR>
elm-momentum             1914/udp  # Elm-Momentum<BR>
facelink                 1915/tcp  # FACELINK<BR>
facelink                 1915/udp  # FACELINK<BR>
persona                  1916/tcp  # Persoft Persona<BR>
persona                  1916/udp  # Persoft Persona<BR>
noagent                  1917/tcp  # NoAgent<BR>
noagent                  1917/udp  # NoAgent<BR>
can-nds                  1918/tcp  # Candle Directory Service - NDS<BR>
can-nds                  1918/udp  # Candle Directory Service - NDS<BR>
can-dch                  1919/tcp  # Candle Directory Service - DCH<BR>
can-dch                  1919/udp  # Candle Directory Service - DCH<BR>
can-ferret               1920/tcp  # Candle Directory Service - FERRET<BR>
can-ferret               1920/udp  # Candle Directory Service - FERRET<BR>
noadmin                  1921/tcp  # NoAdmin<BR>
noadmin                  1921/udp  # NoAdmin<BR>
tapestry                 1922/tcp  # Tapestry<BR>
tapestry                 1922/udp  # Tapestry<BR>
spice                    1923/tcp  # SPICE<BR>
spice                    1923/udp  # SPICE<BR>
xiip                     1924/tcp  # XIIP<BR>
xiip                     1924/udp  # XIIP<BR>
driveappserver           1930/tcp  # Drive App Server<BR>
driveappserver           1930/udp  # Drive App Server<BR>
amdsched                 1931/tcp  # AMD Scheduler<BR>
amdsched                 1931/udp  # AMD Scheduler<BR>
close-combat             1944/tcp  # Close Combat<BR>
close-combat             1944/udp  # Close Combat<BR>
dialogic-elmd            1945/tcp  # dialogic-elmd<BR>
dialogic-elmd            1945/udp  # dialogic-elmd<BR>
tekpls                   1946/tcp  # tekpls<BR>
tekpls                   1946/udp  # tekpls<BR>
hlserver                 1947/tcp  # HL Server<BR>
hlserver                 1947/udp  # HL Server<BR>
eye2eye                  1948/tcp  # eye2eye<BR>
eye2eye                  1948/udp  # eye2eye<BR>
ismaeasdaqlive           1949/tcp  # ISMA Easdaq Live<BR>
ismaeasdaqlive           1949/udp  # ISMA Easdaq Live<BR>
ismaeasdaqtest           1950/tcp  # ISMA Easdaq Test<BR>
ismaeasdaqtest           1950/udp  # ISMA Easdaq Test<BR>
bcs-lmserver             1951/tcp  # bcs-lmserver<BR>
bcs-lmserver             1951/udp  # bcs-lmserver<BR>
mpnjsc                   1952/tcp  # mpnjsc<BR>
mpnjsc                   1952/udp  # mpnjsc<BR>
rapidbase                1953/tcp  # Rapid Base<BR>
rapidbase                1953/udp  # Rapid Base<BR>
bts-appserver            1961/tcp  # BTS App Server<BR>
bts-appserver            1961/udp  # BTS App Server<BR>
solid-e-engine           1964/tcp  # Solid E Engine<BR>
solid-e-engine           1964/udp  # Solid E Engine<BR>
tivoli-npm               1965/tcp  # Tivoli NPM<BR>
tivoli-npm               1965/udp  # Tivoli NPM<BR>
slush                    1966/tcp  # Slush<BR>
slush                    1966/udp  # Slush<BR>
sns-quote                1967/tcp  # SNS Quote<BR>
sns-quote                1967/udp  # SNS Quote<BR>
nfr-flightjacket         1968/tcp  # NFR FlightJacket (New Control Port)<BR><br> Used for mgmt of NFR FlightJacket Intrusion Detection Systems. <BR> <br> NFR Ports: tcp 1968, 2008, 2009 <BR> 
                         /udp  # 
intersys-cache           1972/tcp  # Cache<BR>
intersys-cache           1972/udp  # Cache<BR>
dlsrap                   1973/tcp  # Data Link Switching Remote Access Protocol<BR>
dlsrap                   1973/udp  # Data Link Switching Remote Access Protocol<BR>
drp                      1974/tcp  # DRP<BR>
drp                      1974/udp  # DRP<BR>
banner/tcoflashagent     1975/tcp  # Banner Ad Download<BR><br> Several progs use this port to download banner ads, plus pull some data back up to server (such as what ads were clicked on, etc.). The client piece supporting this is advert.dll. Two progs using this are NetVampire and Go!Zilla. <BR> , TCO Flash Agent<BR>
banner/tcoflashagent     1975/udp  # Banner Ad Download<BR><br> Several progs use this port to download banner ads, plus pull some data back up to server (such as what ads were clicked on, etc.). The client piece supporting this is advert.dll. Two progs using this are NetVampire and Go!Zilla. <BR> , TCO Flash Agent<BR>
tcoregagent              1976/tcp  # TCO Reg Agent<BR>
tcoregagent              1976/udp  # TCO Reg Agent<BR>
tcoaddressbook           1977/tcp  # TCO Address Book<BR>
tcoaddressbook           1977/udp  # TCO Address Book<BR>
unisql                   1978/tcp  # UniSQL<BR>
unisql                   1978/udp  # UniSQL<BR>
unisql-java              1979/tcp  # UniSQL Java<BR>
unisql-java              1979/udp  # UniSQL Java<BR>
shockwave-trojan         1981/tcp  # Backdoor, planted via Shockwave Trojan<BR>Note: This is a backdoor port planted via infected Shockwave software. <BR> 
shockwave-trojan         1981/udp  # Backdoor, planted via Shockwave Trojan<BR>Note: This is a backdoor port planted via infected Shockwave software. <BR> 
bb                       1984/tcp  # BB<BR>
bb                       1984/udp  # BB<BR>
hsrp/foliocorp           1985/tcp  # Hot Standby Router Protocol<BR>, Folio Remote Server<BR>
hsrp/foliocorp           1985/udp  # Hot Standby Router Protocol<BR>, Folio Remote Server<BR>
licensedaemon            1986/tcp  # Cisco License Manager<BR>
licensedaemon            1986/udp  # Cisco License Manager<BR>
tr-rsrb-p1               1987/tcp  # Cisco RSRB Priority 1 port<BR>
tr-rsrb-p1               1987/udp  # Cisco RSRB Priority 1 port<BR>
tr-rsrb-p2               1988/tcp  # Cisco RSRB Priority 2 port<BR>
tr-rsrb-p2               1988/udp  # Cisco RSRB Priority 2 port<BR>
tr-rsrb-p3/mshnet        1989/tcp  # Cisco RSRB Priority 3 port<BR>, MHSnet system<BR>
tr-rsrb-p3/mshnet        1989/udp  # Cisco RSRB Priority 3 port<BR>, MHSnet system<BR>
stun-p1                  1990/tcp  # Cisco STUN Priority 1 port<BR>
stun-p1                  1990/udp  # Cisco STUN Priority 1 port<BR>
stun-p2                  1991/tcp  # Cisco STUN Priority 2 port<BR>
stun-p2                  1991/udp  # Cisco STUN Priority 2 port<BR>
stun-p3/ipsendmsg        1992/tcp  # Cisco STUN Priority 3 port<BR>, IPsendmsg<BR>
stun-p3/ipsendmsg        1992/udp  # Cisco STUN Priority 3 port<BR>, IPsendmsg<BR>
snmp-tcp-port            1993/tcp  # Cisco SNMP TCP port<BR>
snmp-tcp-port            1993/udp  # Cisco SNMP TCP port<BR>
stun-port                1994/tcp  # Cisco serial tunnel port<BR>
stun-port                1994/udp  # Cisco serial tunnel port<BR>
perf-port                1995/tcp  # Cisco perf port<BR>
perf-port                1995/udp  # Cisco perf port<BR>
tr-rsrb-port             1996/tcp  # Cisco Remote SRB port<BR>
tr-rsrb-port             1996/udp  # Cisco Remote SRB port<BR>
gdp-port                 1997/tcp  # Cisco Gateway Discovery Protocol<BR>
gdp-port                 1997/udp  # Cisco Gateway Discovery Protocol<BR>
x25-svc-port             1998/tcp  # Cisco X.25 service (XOT)<BR>
x25-svc-port             1998/udp  # Cisco X.25 service (XOT)<BR>
tcp-id-port              1999/tcp  # Cisco identification port<BR>
tcp-id-port              1999/udp  # Cisco identification port<BR>
callbook/openwin/MikroT Router OS Bandwidth Test Server     2000/tcp  # Callbook<BR>, Sun Openwin<BR><br> Similar to X11, used for remote OpenWindows connections. Vulnerable to spoofing and session hijacking. <BR> , 
callbook/openwin         2000/udp  # Callbook<BR>, Sun Openwin<BR><br> Similar to X11, used for remote OpenWindows connections. Vulnerable to spoofing and session hijacking. <BR> 
glimpse/wizard           2001/tcp  # Glimpse Server Search Engine<BR>, Curry<BR>
wizard/dc/wizard         2001/udp  # Curry<BR>, DC<BR>, wizard<br><br>curry<br>
globe                    2002/tcp  # Globe<BR>
globe                    2002/udp  # Globe<BR>
mailbox                  2004/tcp  # Mailbox<BR>
emce                     2004/udp  # CCWS MM Conf<BR>
berknet                  2005/tcp  # Berknet<BR>
oracle                   2005/udp  # Oracle<BR>
invokator                2006/tcp  # Invokator<BR>
raid-cc                  2006/udp  # RAID-CC<BR>
dectalk                  2007/tcp  # DecTalk<BR>
raid-am                  2007/udp  # RAID-AM<BR>
nfr-flightjacket         2008/tcp  # NFR FlightJacket (Old Control Port)<BR><br> Open on NFR FlightJacket IDS agent, for control comms from manager. <BR> <br> NFR Ports: tcp 1968, 2008, 2009 <BR> 
conf/terminaldb          2008/udp  # conf<BR>, terminaldb<BR>
nfr-flightjacket/news     2009/tcp  # NFR FlightJacket (Old Control Port)<BR><br> Open on NFR FlightJacket IDS Manager, to receive comms from agents. <BR> <br> NFR Ports: tcp 1968, 2008, 2009 <BR> , news<BR>
whosockami               2009/udp  # whosockami<BR>
search                   2010/tcp  # search<BR>
pipe_server              2010/udp  # pipe_server<BR>
raid-cc                  2011/tcp  # RAID-CC<BR>
servserv                 2011/udp  # servserv<BR>
ttyinfo                  2012/tcp  # ttyinfo<BR>
raid-ac                  2012/udp  # RAID-AC<BR>
raid-am                  2013/tcp  # RAID-AM<BR>
raid-cd                  2013/udp  # RAID-CD<BR>
troff                    2014/tcp  # troff<BR>
raid-sf                  2014/udp  # RAID-SF<BR>
cypress                  2015/tcp  # cypress<BR>
raid-cs                  2015/udp  # RAID-CS<BR>
bootserver               2016/tcp  # bootserver<BR>
bootserver               2016/udp  # bootserver<BR>
cypress-stat             2017/tcp  # cypress-stat<BR>
bootclient               2017/udp  # bootclient<BR>
terminaldb               2018/tcp  # terminaldb<BR>
rellpack                 2018/udp  # rellpack<BR>
whosockami               2019/tcp  # whosockami<BR>
about                    2019/udp  # about<BR>
xinupageserver           2020/tcp  # xinupageserver<BR>
xinupageserver           2020/udp  # xinupageserver<BR>
servexec                 2021/tcp  # servexec<BR>
xinuexpansion1           2021/udp  # xinuexpansion1<BR>
down                     2022/tcp  # down<BR>
xinuexpansion2           2022/udp  # xinuexpansion2<BR>
xinuexpansion3           2023/tcp  # xinuexpansion3<BR>
xinuexpansion3           2023/udp  # xinuexpansion3<BR>
xinuexpansion4           2024/tcp  # xinuexpansion4<BR>
xinuexpansion4           2024/udp  # xinuexpansion4<BR>
ellpack                  2025/tcp  # ell pack<BR>
xribs                    2025/udp  # xribs<BR>
scrabble                 2026/tcp  # scrabble<BR>
scrabble                 2026/udp  # scrabble<BR>
shadowserver             2027/tcp  # shadow server<BR>
shadowserver             2027/udp  # shadow server<BR>
submitserver             2028/tcp  # submit server<BR>
submitserver             2028/udp  # submit server<BR>
device2                  2030/tcp  # device2<BR>
device2                  2030/udp  # device2<BR>
blackboard               2032/tcp  # blackboard<BR>
blackboard               2032/udp  # blackboard<BR>
glogger                  2033/tcp  # glogger<BR>
glogger                  2033/udp  # glogger<BR>
scoremgr                 2034/tcp  # score manager<BR>
scoremgr                 2034/udp  # score manager<BR>
imsldoc                  2035/tcp  # imsldoc<BR>
imsldoc                  2035/udp  # imsldoc<BR>
objectmanager            2038/tcp  # object manager<BR>
objectmanager            2038/udp  # object manager<BR>
lam                      2040/tcp  # lab<BR>
lam                      2040/udp  # lab<BR>
interbase                2041/tcp  # interbase<BR>
interbase                2041/udp  # interbase<BR>
isis                     2042/tcp  # isis<BR>
isis                     2042/udp  # isis<BR>
isis-bcast               2043/tcp  # isis-bcast<BR>
isis-bcast               2043/udp  # isis-bcast<BR>
rimsl                    2044/tcp  # rimsl<BR>
rimsl                    2044/udp  # rimsl<BR>
cdfunc                   2045/tcp  # cdfunc<BR>
cdfunc                   2045/udp  # cdfunc<BR>
sdfunc                   2046/tcp  # sdfunc<BR>
sdfunc                   2046/udp  # sdfunc<BR>
dls                      2047/tcp  # dls<BR>
dls                      2047/udp  # dls<BR>
dls-monitor              2048/tcp  # dls-monitor<BR>
dls-monitor              2048/udp  # dls-monitor<BR>
shilp/nfs                2049/tcp  # shilp<BR>, NFS - Sun Microsystems<BR><br> Default port for rpc NFS. <BR> - NFS relies on client host to have already auth'd user (and it assumes there are no rogue hosts or users on network) <BR> - NFS doesn't recheck the client's auth on every request (thus attacker with forged or captured file handle can access exports, even after access perms to original client are terminated [because NFS has no method to cancel a file handle]). <BR> - Intruder bypass the portmapper and directly access tcp 2049, or highport 4045. <BR> <br> CERT Advisory: 95.15. <BR> 
shilp/nfs/shilp          2049/udp  # shilp<BR>, NFS - Sun Microsystems<BR><br> Default port for rpc NFS. <BR> - NFS relies on client host to have already auth'd user (and it assumes there are no rogue hosts or users on network) <BR> - NFS doesn't recheck the client's auth on every request (thus attacker with forged or captured file handle can access exports, even after access perms to original client are terminated [because NFS has no method to cancel a file handle]). <BR> - Intruder bypass the portmapper and directly access tcp 2049, or highport 4045. <BR> <br> CERT Advisory: 95.15. <BR> , shilp<br><br>networked file system, nfs server daemon (clts), nfs server daemon, network file system - sun microsystems, sun nfs, nfs server<br>
knetd                    2053/tcp  # Kerberos de-multiplexer<BR>
                         /udp  # 
rc5des/distrib-netassholes     2064/tcp  # RC5 &amp; DES Cracker; Distributed<BR><br> Port for controlling distributed rc5des password cracking clients. The rc5des prog is a distributed password cracking client package, designed to brute force RC5 and DES encrypted strings using multiple cracking hosts. If port is found open on a host, confirm cracking software presence by locating files: rc5desg.exe, buff-in.rc5, boff-out.rc5 <BR> , distrib-netassholes<br><br>a group of lamers working on a silly closed-source client for solving the rsa cryptographic challenge.  this is the keyblock proxy port.<br>
rc5des                   2064/udp  # RC5 &amp; DES Cracker; Distributed<BR><br> Port for controlling distributed rc5des password cracking clients. The rc5des prog is a distributed password cracking client package, designed to brute force RC5 and DES encrypted strings using multiple cracking hosts. If port is found open on a host, confirm cracking software presence by locating files: rc5desg.exe, buff-in.rc5, boff-out.rc5 <BR> 
dlsrpn                   2065/tcp  # Data Link Switch Read Port Number<BR>
dlsrpn                   2065/udp  # Data Link Switch Read Port Number<BR>
dlswpn                   2067/tcp  # Data Link Switch Write Port Number<BR>
dlswpn                   2067/udp  # Data Link Switch Write Port Number<BR>
lrp                      2090/tcp  # Load Report Protocol<BR>
lrp                      2090/udp  # Load Report Protocol<BR>
prp                      2091/tcp  # PRP<BR>
prp                      2091/udp  # PRP<BR>
descent3                 2092/tcp  # Descent 3<BR>
descent3                 2092/udp  # Descent 3<BR>
nbx-cc                   2093/tcp  # NBX CC<BR>
nbx-cc                   2093/udp  # NBX CC<BR>
nbx-au                   2094/tcp  # NBX AU<BR>
nbx-au                   2094/udp  # NBX AU<BR>
nbx-ser                  2095/tcp  # NBX SER<BR>
nbx-ser                  2095/udp  # NBX SER<BR>
nbx-dir                  2096/tcp  # NBX DIR<BR>
nbx-dir                  2096/udp  # NBX DIR<BR>
jetformpreview           2097/tcp  # Jet Form Preview<BR>
jetformpreview           2097/udp  # Jet Form Preview<BR>
dialog-port              2098/tcp  # Dialog Port<BR>
dialog-port              2098/udp  # Dialog Port<BR>
h2250-annex-g            2099/tcp  # H.225.0 Annex G<BR>
h2250-annex-g            2099/udp  # H.225.0 Annex G<BR>
amiganetfs               2100/tcp  # amiganetfs<BR>
amiganetfs               2100/udp  # amiganetfs<BR>
rtcm-sc104               2101/tcp  # rtcm-sc104<BR>
rtcm-sc104               2101/udp  # rtcm-sc104<BR>
zephyr-srv               2102/tcp  # Zephyr server<BR>
zephyr-srv               2102/udp  # Zephyr server<BR>
zephyr-clt               2103/tcp  # Zephyr serv-hm connection<BR>
zephyr-clt               2103/udp  # Zephyr serv-hm connection<BR>
zephyr-hm                2104/tcp  # Zephyr hostmanager<BR>
zephyr-hm                2104/udp  # Zephyr hostmanager<BR>
eklogin/minipay          2105/tcp  # Kerberos encrypted rlogon<BR>, MiniPay<BR>
minipay/minipay          2105/udp  # MiniPay<BR>, minipay<br><br>kerberos (v4) encrypted rlogin, minipay<br>
mzap                     2106/tcp  # MZAP<BR>
mzap/mzap                2106/udp  # MZAP<BR>, mzap<br><br>kerberos (v4) encrypted rshell, mzap<br>
bintec-admin             2107/tcp  # BinTec Admin<BR>
bintec-admin             2107/udp  # BinTec Admin<BR>
ergolight                2108/tcp  # Ergolight<BR>
ergolight/comcam         2108/udp  # Ergolight<BR>, comcam<br><br>comcam, kerberos (v4) remote initialization<br>
x-bone-api               2165/tcp  # X-Bone API<BR>
x-bone-api               2165/udp  # X-Bone API<BR>
mc-gt-srv                2180/tcp  # Millicent Vendor Gateway Server<BR>
mc-gt-srv                2180/udp  # Millicent Vendor Gateway Server<BR>
eforward                 2181/tcp  # eforward<BR>
eforward                 2181/udp  # eforward<BR>
ici                      2200/tcp  # ICI<BR>
ici                      2200/udp  # ICI<BR>
ats                      2201/tcp  # Advanced Training System Program<BR>
ats                      2201/udp  # Advanced Training System Program<BR>
imtc-map                 2202/tcp  # Int. Multimedia Teleconf. Cosortium<BR>
imtc-map                 2202/udp  # Int. Multimedia Teleconf. Cosortium<BR>
kali                     2213/tcp  # Kali<BR>
kali                     2213/udp  # Kali<BR>
ganymede                 2220/tcp  # Ganymede<BR>
ganymede                 2220/udp  # Ganymede<BR>
rockwell-csp1/unreg-ab1     2221/tcp  # Rockwell CSP1<BR>, Allen-Bradley unregistered port<BR>
rockwell-csp1/unreg-ab1     2221/udp  # Rockwell CSP1<BR>, Allen-Bradley unregistered port<BR>
rockwell-csp2/unreg-ab2/DirectAdmin     2222/tcp  # Rockwell CSP2<BR>, Allen-Bradley unregistered port<BR>, Direct Admin - http://www.directadmin.com
rockwell-csp2/unreg-ab2     2222/udp  # Rockwell CSP2<BR>, Allen-Bradley unregistered port<BR>
rockwell-csp3/inreg-ab3     2223/tcp  # Rockwell CSP3<BR>, Allen-Bradley unregistered port<BR>
rockwell-csp3/inreg-ab3     2223/udp  # Rockwell CSP3<BR>, Allen-Bradley unregistered port<BR>
ivs-video                2232/tcp  # IVS Video default<BR>
ivs-video                2232/udp  # IVS Video default<BR>
infocrypt                2233/tcp  # INFOCRYPT<BR>
infocrypt                2233/udp  # INFOCRYPT<BR>
directplay               2234/tcp  # DirectPlay<BR>
directplay               2234/udp  # DirectPlay<BR>
sercomm-wlink            2235/tcp  # Sercomm-WLink<BR>
sercomm-wlink            2235/udp  # Sercomm-WLink<BR>
nani                     2236/tcp  # Nani<BR>
nani                     2236/udp  # Nani<BR>
optech-port1-lm          2237/tcp  # Optech Port1 License Manager<BR>
optech-port1-lm          2237/udp  # Optech Port1 License Manager<BR>
aviva-sna                2238/tcp  # AVIVA SNA SERVER<BR>
aviva-sna                2238/udp  # AVIVA SNA SERVER<BR>
imagequery               2239/tcp  # Image Query<BR>
imagequery               2239/udp  # Image Query<BR>
recipe                   2240/tcp  # Recipe<BR>
recipe                   2240/udp  # Recipe<BR>
ivsd                     2241/tcp  # IVS Daemon<BR>
ivsd                     2241/udp  # IVS Daemon<BR>
foliocorp                2242/tcp  # Folio Remote Server<BR>
foliocorp                2242/udp  # Folio Remote Server<BR>
magicom                  2243/tcp  # Magicom Protocol<BR>
magicom                  2243/udp  # Magicom Protocol<BR>
nmsserver/ctaccess       2244/tcp  # NMS Server<BR>, Natural MicroSystem CTAccess Server, www.nmscommunications.com
nmsserver                2244/udp  # NMS Server<BR>
hao                      2245/tcp  # HaO<BR>
hao                      2245/udp  # HaO<BR>
xmquery                  2279/tcp  # xmquery<BR>
xmquery                  2279/udp  # xmquery<BR>
lnvpoller                2280/tcp  # LNVPOLLER<BR>
lnvpoller                2280/udp  # LNVPOLLER<BR>
lnvconsole               2281/tcp  # LNVCONSOLE<BR>
lnvconsole               2281/udp  # LNVCONSOLE<BR>
lnvalarm                 2282/tcp  # LNVALARM<BR>
lnvalarm                 2282/udp  # LNVALARM<BR>
lnvstatus                2283/tcp  # LNVSTATUS<BR>
lnvstatus                2283/udp  # LNVSTATUS<BR>
lnvmaps                  2284/tcp  # LNVMAPS<BR>
lnvmaps                  2284/udp  # LNVMAPS<BR>
lnvmailmon               2285/tcp  # LNVMAILMON<BR>
lnvmailmon               2285/udp  # LNVMAILMON<BR>
nas-metering             2286/tcp  # NAS-Metering<BR>
nas-metering             2286/udp  # NAS-Metering<BR>
dna                      2287/tcp  # DNA<BR>
dna                      2287/udp  # DNA<BR>
netml                    2288/tcp  # NETML<BR>
netml                    2288/udp  # NETML<BR>
konshus-lm               2294/tcp  # Konsus License Manager (FLEX)<BR>
konshus-lm               2294/udp  # Konsus License Manager (FLEX)<BR>
advant-lm                2295/tcp  # Advant License Manager<BR>
advant-lm                2295/udp  # Advant License Manager<BR>
theta-lm                 2296/tcp  # Theta License Manager (Rainbow)<BR>
theta-lm                 2296/udp  # Theta License Manager (Rainbow)<BR>
d2k-datamover1           2297/tcp  # D2K DataMover1<BR>
d2k-datamover1           2297/udp  # D2K DataMover1<BR>
d2k-datamover2           2298/tcp  # D2K DataMover2<BR>
d2k-datamover2           2298/udp  # D2K DataMover2<BR>
pc-telecommute           2299/tcp  # PC Telecommute<BR>
pc-telecommute           2299/udp  # PC Telecommute<BR>
cvmmon                   2300/tcp  # CVMMON<BR>
cvmmon                   2300/udp  # CVMMON<BR>
cpq-wbem                 2301/tcp  # Compaq HTTP<BR>
cpq-wbem                 2301/udp  # Compaq HTTP<BR>
binderysupport           2302/tcp  # Bindery Support<BR>
binderysupport           2302/udp  # Bindery Support<BR>
proxy-gateway            2303/tcp  # Proxy Gateway<BR>
proxy-gateway            2303/udp  # Proxy Gateway<BR>
attachmate-uts           2304/tcp  # Attachmate UTS<BR>
attachmate-uts           2304/udp  # Attachmate UTS<BR>
mt-scaleserver           2305/tcp  # MT ScaleServer<BR>
mt-scaleserver           2305/udp  # MT ScaleServer<BR>
tappi-boxnet             2306/tcp  # TAPPI BoxNet<BR>
tappi-boxnet             2306/udp  # TAPPI BoxNet<BR>
pehelp                   2307/tcp  # pehelp<BR>
pehelp                   2307/udp  # pehelp<BR>
sdhelp                   2308/tcp  # sdhelp<BR>
sdhelp                   2308/udp  # sdhelp<BR>
sdserver                 2309/tcp  # SD Server<BR>
sdserver                 2309/udp  # SD Server<BR>
sdclient                 2310/tcp  # SD Client<BR>
sdclient                 2310/udp  # SD Client<BR>
messageserver/messageservice     2311/tcp  # Message Service<BR>, messageservice<br><br>message service<br>
messageserver/messageservice     2311/udp  # Message Service<BR>, messageservice<br><br>message service<br>
iapp                     2313/tcp  # IAPP<BR>
iapp                     2313/udp  # IAPP<BR>
cr-websystems            2314/tcp  # CR WebSystems<BR>
cr-websystems            2314/udp  # CR WebSystems<BR>
precise-sft              2315/tcp  # Precise Sft.<BR>
precise-sft              2315/udp  # Precise Sft.<BR>
sent-lm                  2316/tcp  # SENT License Manager<BR>
sent-lm                  2316/udp  # SENT License Manager<BR>
attachmate-g32           2317/tcp  # Attachmate G32<BR>
attachmate-g32           2317/udp  # Attachmate G32<BR>
cadencecontrol           2318/tcp  # Cadence Control<BR>
cadencecontrol           2318/udp  # Cadence Control<BR>
infolibria               2319/tcp  # InfoLibria<BR>
infolibria               2319/udp  # InfoLibria<BR>
siebel-ns                2320/tcp  # Siebel NS<BR>
siebel-ns                2320/udp  # Siebel NS<BR>
rdlap                    2321/tcp  # RDLAP<BR>
rdlap/rdlap              2321/udp  # RDLAP<BR>, rdlap<br><br>rdlap<br>
ofsd                     2322/tcp  # ofsd<BR>
ofsd                     2322/udp  # ofsd<BR>
3d-nfsd                  2323/tcp  # 3d-nfsd<BR>
3d-nfsd                  2323/udp  # 3d-nfsd<BR>
cosmocall                2324/tcp  # Cosmocall<BR>
cosmocall                2324/udp  # Cosmocall<BR>
designspace-lm           2325/tcp  # Design Space License Manager<BR>
designspace-lm           2325/udp  # Design Space License Manager<BR>
idcp                     2326/tcp  # IDCP<BR>
idcp                     2326/udp  # IDCP<BR>
xingcsm                  2327/tcp  # xingsm<BR>
xingcsm/netscape         2327/udp  # xingsm<BR>, Netscape Audio-Conferencing<BR>Note: Also see tcp 6498 &amp; 6502 <BR> 
netrix-sftm              2328/tcp  # Netrix SFTM<BR>
netrix-sftm              2328/udp  # Netrix SFTM<BR>
nvd                      2329/tcp  # NVD<BR>
nvd                      2329/udp  # NVD<BR>
tscchat                  2330/tcp  # TSCCHAT<BR>
tscchat                  2330/udp  # TSCCHAT<BR>
agentview                2331/tcp  # AGENTVIEW<BR>
agentview                2331/udp  # AGENTVIEW<BR>
rcc-host                 2332/tcp  # RCC Host<BR>
rcc-host                 2332/udp  # RCC Host<BR>
snapp                    2333/tcp  # SNAPP<BR>
snapp                    2333/udp  # SNAPP<BR>
ace-client               2334/tcp  # ACE Client Auth<BR>
ace-client               2334/udp  # ACE Client Auth<BR>
ace-proxy                2335/tcp  # ACE Proxy<BR>
ace-proxy                2335/udp  # ACE Proxy<BR>
appleugcontrol           2336/tcp  # Apple UG Control<BR>
appleugcontrol           2336/udp  # Apple UG Control<BR>
ideesr/ideesrv           2337/tcp  # ideesrv<BR>, ideesrv<br><br>ideesrv<br>
ideesr/ideesrv           2337/udp  # ideesrv<BR>, ideesrv<br><br>ideesrv<br>
norton-lambert           2338/tcp  # Norton Lambert<BR>
norton-lambert           2338/udp  # Norton Lambert<BR>
3com-webview             2339/tcp  # 3com Webview<BR>
3com-webview             2339/udp  # 3com Webview<BR>
wrs_registry             2340/tcp  # WRS Registry<BR>
wrs_registry             2340/udp  # WRS Registry<BR>
xiostatus                2341/tcp  # CIO Status<BR>
xiostatus                2341/udp  # CIO Status<BR>
manage-exec              2342/tcp  # Seagate Manage Exec<BR>
manage-exec              2342/udp  # Seagate Manage Exec<BR>
nati-logos               2343/tcp  # nati logos<BR>
nati-logos               2343/udp  # nati logos<BR>
fcmsys                   2344/tcp  # fcmsys<BR>
fcmsys                   2344/udp  # fcmsys<BR>
dbm                      2345/tcp  # dbm<BR>
dbm                      2345/udp  # dbm<BR>
redstorm_join            2346/tcp  # Game Connection Port<BR>
redstorm_join            2346/udp  # Game Connection Port<BR>
redstorm_find            2347/tcp  # Game Announcement and Location<BR>
redstorm_find            2347/udp  # Game Announcement and Location<BR>
redstorm_info            2348/tcp  # Info to query for game status<BR>
redstorm_info            2348/udp  # Info to query for game status<BR>
redstorm_diag            2349/tcp  # Diagnostics Port<BR>
redstorm_diag/redstorm_diag     2349/udp  # Diagnostics Port<BR>, redstorm_diag<br><br>disgnostics port<br>
psbserver                2350/tcp  # psbserver<BR>
psbserver                2350/udp  # psbserver<BR>
psrserver                2351/tcp  # psrserver<BR>
psrserver                2351/udp  # psrserver<BR>
pslserver                2352/tcp  # pslserver<BR>
pslserver                2352/udp  # pslserver<BR>
pspserver                2353/tcp  # pspserver<BR>
pspserver                2353/udp  # pspserver<BR>
psprserver               2354/tcp  # psprserver<BR>
psprserver               2354/udp  # psprserver<BR>
psdbserver               2355/tcp  # psdbserver<BR>
psdbserver               2355/udp  # psdbserver<BR>
gxtelmd                  2356/tcp  # GXT License Management<BR>
gxtelmd                  2356/udp  # GXT License Management<BR>
unihub-server            2357/tcp  # UniHub Server<BR>
unihub-server            2357/udp  # UniHub Server<BR>
futrix                   2358/tcp  # Futrix<BR>
futrix                   2358/udp  # Futrix<BR>
flukeserver              2359/tcp  # FlukeServer<BR>
flukeserver              2359/udp  # FlukeServer<BR>
nexstorindltd            2360/tcp  # NexstorIndLtd<BR>
nexstorindltd            2360/udp  # NexstorIndLtd<BR>
tl1                      2361/tcp  # TL1<BR>
tl1                      2361/udp  # TL1<BR>
digiman                  2362/tcp  # Digiman<BR>
digiman                  2362/udp  # Digiman<BR>
mediacntrlnfsd           2363/tcp  # Media Central NFSD<BR>
mediacntrlnfsd           2363/udp  # Media Central NFSD<BR>
oi-2000                  2364/tcp  # OI-2000<BR>
oi-2000                  2364/udp  # OI-2000<BR>
dbref                    2365/tcp  # dbref<BR>
dbref                    2365/udp  # dbref<BR>
qip-login                2366/tcp  # qup-login<BR>
qip-login                2366/udp  # qup-login<BR>
service-ctrl             2367/tcp  # Service Control<BR>
service-ctrl             2367/udp  # Service Control<BR>
opentable                2368/tcp  # OpenTable<BR>
opentable                2368/udp  # OpenTable<BR>
acs2000-dsp              2369/tcp  # ACS2000 DSP<BR>
acs2000-dsp              2369/udp  # ACS2000 DSP<BR>
l3-hbmon                 2370/tcp  # L3-HBMon<BR>
l3-hbmon                 2370/udp  # L3-HBMon<BR>
compaq-https             2381/tcp  # Compaq HTTPS<BR>
compaq-https             2381/udp  # Compaq HTTPS<BR>
ms-olap3                 2382/tcp  # MS OLAP 3<BR>
ms-olap3                 2382/udp  # MS OLAP 3<BR>
ms-olap4                 2383/tcp  # MS OLAP 4<BR>
ms-olap4                 2383/udp  # MS OLAP 4<BR>
ovsessionmgr             2389/tcp  # OpenView Session Manager<BR>
ovsessionmgr             2389/udp  # OpenView Session Manager<BR>
rsmtp                    2390/tcp  # RSMTP<BR>
rsmtp                    2390/udp  # RSMTP<BR>
3com-net-mgmt            2391/tcp  # 3COM Net Management<BR>
3com-net-mgmt            2391/udp  # 3COM Net Management<BR>
tacticalauth             2392/tcp  # Tactical Auth<BR>
tacticalauth             2392/udp  # Tactical Auth<BR>
ms-olap1                 2393/tcp  # MS OLAP 1<BR>
ms-olap1                 2393/udp  # MS OLAP 1<BR>
ms-olap2                 2394/tcp  # MS OLAP 2<BR>
ms-olap2/ms-olap2        2394/udp  # MS OLAP 2<BR>, ms-olap2<br><br>ma olap 2<br>
lan900_remote            2395/tcp  # LAN900 Remote<BR>
lan900_remote            2395/udp  # LAN900 Remote<BR>
wusage                   2396/tcp  # Wusage<BR>
wusage                   2396/udp  # Wusage<BR>
ncl                      2397/tcp  # NCL<BR>
ncl                      2397/udp  # NCL<BR>
orbiter                  2398/tcp  # Orbiter<BR>
orbiter                  2398/udp  # Orbiter<BR>
fmpro-fdal               2399/tcp  # FileMaker, Inc. - Data Access Layer<BR>
fmpro-fdal               2399/udp  # FileMaker, Inc. - Data Access Layer<BR>
opequus-server           2400/tcp  # OpEquus Server<BR>
opequus-server           2400/udp  # OpEquus Server<BR>
cvspserver               2401/tcp  # cvspserver<BR>
cvspserver               2401/udp  # cvspserver<BR>
taskmaster2000           2402/tcp  # TaskMaster 2000 Server<BR>
taskmaster2000           2402/udp  # TaskMaster 2000 Server<BR>
taskmaster2000           2403/tcp  # TaskMaster 2000 Web<BR>
taskmaster2000           2403/udp  # TaskMaster 2000 Web<BR>
iec870-5-104             2404/tcp  # IEC870-5-104<BR>
iec870-5-104             2404/udp  # IEC870-5-104<BR>
trc-netpoll              2405/tcp  # TRC Netpoll<BR>
trc-netpoll              2405/udp  # TRC Netpoll<BR>
jediserver               2406/tcp  # JediServer<BR>
jediserver               2406/udp  # JediServer<BR>
orion                    2407/tcp  # Orion<BR>
orion                    2407/udp  # Orion<BR>
optimanet                2408/tcp  # OptimaNet<BR>
optimanet                2408/udp  # OptimaNet<BR>
sns-protocol             2409/tcp  # SNS Protocol<BR>
sns-protocol             2409/udp  # SNS Protocol<BR>
vrts-registry            2410/tcp  # VRTS Registry<BR>
vrts-registry            2410/udp  # VRTS Registry<BR>
netwave-ap-mgmt          2411/tcp  # Netwave AP Management<BR>
netwave-ap-mgmt          2411/udp  # Netwave AP Management<BR>
cdn                      2412/tcp  # CDN<BR>
cdn                      2412/udp  # CDN<BR>
orion-rmi-reg            2413/tcp  # orion-rmi-reg<BR>
orion-rmi-reg            2413/udp  # orion-rmi-reg<BR>
interlinua/interlingua     2414/tcp  # Interlingua<BR>, interlingua<br><br>interlingua<br>
interlinua/interlingua     2414/udp  # Interlingua<BR>, interlingua<br><br>interlingua<br>
comtest                  2415/tcp  # COMTEST<BR>
comtest                  2415/udp  # COMTEST<BR>
rmtserver                2416/tcp  # RMT Server<BR>
rmtserver                2416/udp  # RMT Server<BR>
composit-server          2417/tcp  # Composit Server<BR>
composit-server          2417/udp  # Composit Server<BR>
cas                      2418/tcp  # cas<BR>
cas                      2418/udp  # cas<BR>
attachmate-s2s           2419/tcp  # Attachmate S2S<BR>
attachmate-s2s           2419/udp  # Attachmate S2S<BR>
dslremote-mgmt           2420/tcp  # DSL Remote Management<BR>
dslremote-mgmt           2420/udp  # DSL Remote Management<BR>
g-talk                   2421/tcp  # G-Talk<BR>
g-talk                   2421/udp  # G-Talk<BR>
crmsbits                 2422/tcp  # CRMSBITS<BR>
crmsbits                 2422/udp  # CRMSBITS<BR>
rnrp                     2423/tcp  # RNRP<BR>
rnrp                     2423/udp  # RNRP<BR>
kofax-svr                2424/tcp  # LPFAX-SVR<BR>
kofax-svr                2424/udp  # LPFAX-SVR<BR>
fjitsuappmgr             2425/tcp  # Fujitsu App Manager<BR>
fjitsuappmgr             2425/udp  # Fujitsu App Manager<BR>
applianttcp              2426/tcp  # Applicant TCP<BR>
appliantudp              2426/udp  # Applicant UDP<BR>
stgcp/mgcp-gateway       2427/tcp  # Simple Telephony Gateway Control Protocol<BR>, Media Gateway Control Protocol Gateway<BR>
stgcp/mgcp-gateway       2427/udp  # Simple Telephony Gateway Control Protocol<BR>, Media Gateway Control Protocol Gateway<BR>
ott                      2428/tcp  # One-way Trip Timer<BR>
ott                      2428/udp  # One-way Trip Timer<BR>
ft-role                  2429/tcp  # FT-ROLE<BR>
ft-role                  2429/udp  # FT-ROLE<BR>
venus                    2430/tcp  # venus<BR>
venus                    2430/udp  # venus<BR>
venus-se                 2431/tcp  # venus-se<BR>
venus-se                 2431/udp  # venus-se<BR>
codasrv                  2432/tcp  # codasrv<BR>
codasrv                  2432/udp  # codasrv<BR>
codasrv-se               2433/tcp  # cosasrv-se<BR>
codasrv-se               2433/udp  # cosasrv-se<BR>
pxc-epmap                2434/tcp  # pxc-epmap<BR>
pxc-epmap                2434/udp  # pxc-epmap<BR>
optilogic                2435/tcp  # OptiLogic<BR>
optilogic                2435/udp  # OptiLogic<BR>
topx                     2436/tcp  # TOP/X<BR>
topx                     2436/udp  # TOP/X<BR>
unicontrol               2437/tcp  # UniControl<BR>
unicontrol               2437/udp  # UniControl<BR>
msp                      2438/tcp  # MSP<BR>
msp                      2438/udp  # MSP<BR>
sybasedbsynch            2439/tcp  # SybaseDBSynch<BR>
sybasedbsynch            2439/udp  # SybaseDBSynch<BR>
spearway                 2440/tcp  # Spearway Lockers<BR>
spearway/spearway        2440/udp  # Spearway Lockers<BR>, spearway<br><br>spearway lockser<br>
pvsw-inet                2441/tcp  # pvsw-inet<BR>
pvsw-inet                2441/udp  # pvsw-inet<BR>
netangel                 2442/tcp  # Netangel<BR>
netangel                 2442/udp  # Netangel<BR>
powerclientcsf           2443/tcp  # PowerClient Central Storage Facility<BR>
powerclientcsf           2443/udp  # PowerClient Central Storage Facility<BR>
btpp2sectrans            2444/tcp  # BT PP2 Sectrans<BR>
btpp2sectrans            2444/udp  # BT PP2 Sectrans<BR>
dtn1                     2445/tcp  # DTN1<BR>
dtn1                     2445/udp  # DTN1<BR>
bues_service             2446/tcp  # bues_service<BR>
bues_service             2446/udp  # bues_service<BR>
ovwdb                    2447/tcp  # OpenView NNM daemon<BR>
ovwdb                    2447/udp  # OpenView NNM daemon<BR>
hpppssvr                 2448/tcp  # hpppssvr<BR>
hpppssvr                 2448/udp  # hpppssvr<BR>
ratl                     2449/tcp  # RATL<BR>
ratl                     2449/udp  # RATL<BR>
netadmin                 2450/tcp  # netadmin<BR>
netadmin                 2450/udp  # netadmin<BR>
netchat                  2451/tcp  # netchat<BR>
netchat                  2451/udp  # netchat<BR>
snifferclient            2452/tcp  # SnifferClient<BR>
snifferclient            2452/udp  # SnifferClient<BR>
madge-om                 2453/tcp  # madge-om<BR>
madge-om                 2453/udp  # madge-om<BR>
indx-dds                 2454/tcp  # IndX-DDS<BR>
indx-dds                 2454/udp  # IndX-DDS<BR>
wago-io-system           2455/tcp  # WAGO-IO-SYSTEM<BR>
wago-io-system           2455/udp  # WAGO-IO-SYSTEM<BR>
altav-remmgt             2456/tcp  # altav-remmgt<BR>
altav-remmgt             2456/udp  # altav-remmgt<BR>
rapido-ip                2457/tcp  # Rapico_IP<BR>
rapido-ip                2457/udp  # Rapico_IP<BR>
griffin                  2458/tcp  # griffin<BR>
griffin                  2458/udp  # griffin<BR>
community                2459/tcp  # Community<BR>
community                2459/udp  # Community<BR>
ms-theater               2460/tcp  # ms-theater<BR>
ms-theater               2460/udp  # ms-theater<BR>
qadmifoper               2461/tcp  # qadmifoper<BR>
qadmifoper               2461/udp  # qadmifoper<BR>
qadmifevent              2462/tcp  # qadmifevent<BR>
qadmifevent              2462/udp  # qadmifevent<BR>
symbios-raid             2463/tcp  # Symbios Raid<BR>
symbios-raid             2463/udp  # Symbios Raid<BR>
direcpc-si               2464/tcp  # DirecPC SI<BR>
direcpc-si               2464/udp  # DirecPC SI<BR>
lbm                      2465/tcp  # Load Balance Management<BR>
lbm                      2465/udp  # Load Balance Management<BR>
lbf                      2466/tcp  # Load Balance Forwarding<BR>
lbf                      2466/udp  # Load Balance Forwarding<BR>
high-criteria            2467/tcp  # High Criteria<BR>
high-criteria            2467/udp  # High Criteria<BR>
qip_msgd/qip-msgd        2468/tcp  # qip_msgd<BR>, qip-msgd<br><br>qip_msgd<br>
qip_msgd/qip-msgd        2468/udp  # qip_msgd<BR>, qip-msgd<br><br>qip_msgd<br>
mti-tcs-comm             2469/tcp  # MTI-TCS-COMM<BR>
mti-tcs-comm             2469/udp  # MTI-TCS-COMM<BR>
taskman_port/taskman-port     2470/tcp  # taskman port<BR>, taskman-port<br><br>taskman port<br>
taskman_port/taskman-port     2470/udp  # taskman port<BR>, taskman-port<br><br>taskman port<br>
seaodbc                  2471/tcp  # SeaODBC<BR>
seaodbc                  2471/udp  # SeaODBC<BR>
c3                       2472/tcp  # C3<BR>
c3                       2472/udp  # C3<BR>
aker-cdp                 2473/tcp  # Aker-cdp<BR>
aker-cdp                 2473/udp  # Aker-cdp<BR>
vitalanalysis            2474/tcp  # Vital Analysis<BR>
vitalanalysis            2474/udp  # Vital Analysis<BR>
ace-server               2475/tcp  # ACE Server<BR>
ace-server               2475/udp  # ACE Server<BR>
ace-svr-prop             2476/tcp  # ACE Server Propagation<BR>
ace-svr-prop             2476/udp  # ACE Server Propagation<BR>
ssm-cvs                  2477/tcp  # SecurSight Certificate Valifation Service<BR>
ssm-cvs                  2477/udp  # SecurSight Certificate Valifation Service<BR>
ssm-cssps                2478/tcp  # SecurSight Authentication Server (SSL)<BR>
ssm-cssps/ssm-cssps      2478/udp  # SecurSight Authentication Server (SSL)<BR>, ssm-cssps<br><br>secursight authentication server (ssl)<br>
ssm-els                  2479/tcp  # SecurSight Event Logging Server (SSL)<BR>
ssm-els                  2479/udp  # SecurSight Event Logging Server (SSL)<BR>
lingwood                 2480/tcp  # Lingwood's Detail<BR>
lingwood                 2480/udp  # Lingwood's Detail<BR>
giop                     2481/tcp  # Oracle GIOP<BR>
giop                     2481/udp  # Oracle GIOP<BR>
giop-ssl                 2482/tcp  # Oracle GIOP SSL<BR>
giop-ssl                 2482/udp  # Oracle GIOP SSL<BR>
ttc                      2483/tcp  # Oracle TTC<BR>
ttc/ttc                  2483/udp  # Oracle TTC<BR>, ttc<br><br>oracel ttc<br>
ttc-ssl                  2484/tcp  # Oracle TTC SSL<BR>
ttc-ssl                  2484/udp  # Oracle TTC SSL<BR>
netobjects1              2485/tcp  # NetObjects1<BR>
netobjects1              2485/udp  # NetObjects1<BR>
netobjects2              2486/tcp  # NetObjects2<BR>
netobjects2              2486/udp  # NetObjects2<BR>
pns                      2487/tcp  # Policy Notice Service<BR>
pns                      2487/udp  # Policy Notice Service<BR>
moy-corp                 2488/tcp  # Moy Corporation<BR>
moy-corp                 2488/udp  # Moy Corporation<BR>
tsilb                    2489/tcp  # TSILB<BR>
tsilb                    2489/udp  # TSILB<BR>
qip_qdhcp/qip-qdhcp      2490/tcp  # qip_qdhcp<BR>, qip-qdhcp<br><br>qip_qdhcp<br>
qip_qdhcp/qip-qdhcp      2490/udp  # qip_qdhcp<BR>, qip-qdhcp<br><br>qip_qdhcp<br>
conclave-cpp             2491/tcp  # Conclave CPP<BR>
conclave-cpp             2491/udp  # Conclave CPP<BR>
groove                   2492/tcp  # GROOVE<BR>
groove                   2492/udp  # GROOVE<BR>
talarian-mqs             2493/tcp  # Talarian MQS<BR>
talarian-mqs             2493/udp  # Talarian MQS<BR>
bmc-ar                   2494/tcp  # BMC AR<BR>
bmc-ar                   2494/udp  # BMC AR<BR>
fast-rem-serv            2495/tcp  # Fast Remote Services<BR>
fast-rem-serv            2495/udp  # Fast Remote Services<BR>
dirgis                   2496/tcp  # DIRGIS<BR>
dirgis                   2496/udp  # DIRGIS<BR>
quaddb                   2497/tcp  # Quad DB<BR>
quaddb                   2497/udp  # Quad DB<BR>
odn-castraq              2498/tcp  # ODN-CasTraq<BR>
odn-castraq              2498/udp  # ODN-CasTraq<BR>
unicontrol               2499/tcp  # UniControl<BR>
unicontrol               2499/udp  # UniControl<BR>
rtsserv                  2500/tcp  # Resource Tracking System Server<BR>
rtsserv                  2500/udp  # Resource Tracking System Server<BR>
rtsclient                2501/tcp  # Resource Tracking System Client<BR>
rtsclient                2501/udp  # Resource Tracking System Client<BR>
kentrox-prot             2502/tcp  # Kentrox Protocol<BR>
kentrox-prot             2502/udp  # Kentrox Protocol<BR>
nms-dpnss                2503/tcp  # NMS-DPNSS
nms-dpnss                2503/udp  # NMS-DPNSS
wlbs                     2504/tcp  # SLBS<BR>
wlbs/wlbs                2504/udp  # WLBS<br> Used in NT/Win2000 clustering.<BR> , SLBS<BR>
torque-traffic           2505/tcp  # torque-traffic<BR>
torque-traffic           2505/udp  # torque-traffic<BR>
jbroker                  2506/tcp  # jbroker<BR>
jbroker                  2506/udp  # jbroker<BR>
spock                    2507/tcp  # spock<BR>
spock                    2507/udp  # spock<BR>
jdatastore               2508/tcp  # JDataStore<BR>
jdatastore               2508/udp  # JDataStore<BR>
fjmpss                   2509/tcp  # fjmpss<BR>
fjmpss                   2509/udp  # fjmpss<BR>
fjappmgrbulk             2510/tcp  # fjappmgrbulk<BR>
fjappmgrbulk             2510/udp  # fjappmgrbulk<BR>
metastorm                2511/tcp  # Metastorm<BR>
metastorm                2511/udp  # Metastorm<BR>
citrixima                2512/tcp  # Citrix IMA<BR>
citrixima                2512/udp  # Citrix IMA<BR>
citrixadmin              2513/tcp  # Citrix Admin<BR>
citrixadmin              2513/udp  # Citrix Admin<BR>
facsys-ntp               2514/tcp  # Facsys NTP<BR>
facsys-ntp               2514/udp  # Facsys NTP<BR>
facsys-router            2515/tcp  # Facsys Router<BR>
facsys-router            2515/udp  # Facsys Router<BR>
maincontrol              2516/tcp  # Main Control<BR>
maincontrol              2516/udp  # Main Control<BR>
call-sig-trans           2517/tcp  # Call Signalling Transport<BR>
call-sig-trans           2517/udp  # Call Signalling Transport<BR>
willy                    2518/tcp  # Willy<BR>
willy                    2518/udp  # Willy<BR>
globmsgsvc               2519/tcp  # globmsgsvc<BR>
globmsgsvc               2519/udp  # globmsgsvc<BR>
pvsw                     2520/tcp  # pvsw<BR>
pvsw                     2520/udp  # pvsw<BR>
adaptexmgr/adaptecmgr     2521/tcp  # Adaptec Manager<BR>, adaptecmgr<br><br>adaptec manager<br>
adaptexmgr/adaptecmgr     2521/udp  # Adaptec Manager<BR>, adaptecmgr<br><br>adaptec manager<br>
windb                    2522/tcp  # WinDb<BR>
windb                    2522/udp  # WinDb<BR>
qke-11c-v3/qke-llc-v3     2523/tcp  # Qke LLC V.3<BR>, qke-llc-v3<br><br>qke llc v.3<br>
qke-11c-v3/qke-llc-v3     2523/udp  # Qke LLC V.3<BR>, qke-llc-v3<br><br>qke llc v.3<br>
optiwave-1m/optiwave-lm     2524/tcp  # Optiwave License Manager<BR>, optiwave-lm<br><br>optiwave license management<br>
optiwave-1m/optiwave-lm     2524/udp  # Optiwave License Manager<BR>, optiwave-lm<br><br>optiwave license management<br>
ms-v-worlds              2525/tcp  # MS V-Worlds<BR>
ms-v-worlds              2525/udp  # MS V-Worlds<BR>
ema-sent-lm              2526/tcp  # EMA License Manager<BR>
ema-sent-lm              2526/udp  # EMA License Manager<BR>
iqserver                 2527/tcp  # IQ Server<BR>
iqserver                 2527/udp  # IQ Server<BR>
ncr_ccl                  2528/tcp  # NCR CCL<BR>
ncr_ccl                  2528/udp  # NCR CCL<BR>
utsftp                   2529/tcp  # UTS FTP<BR>
utsftp                   2529/udp  # UTS FTP<BR>
vrcommerce               2530/tcp  # VR Commerce<BR>
vrcommerce               2530/udp  # VR Commerce<BR>
ito-e-gui                2531/tcp  # ITO-E GUI<BR>
ito-e-gui                2531/udp  # ITO-E GUI<BR>
ovtopmd                  2532/tcp  # OVTOPMD<BR>
ovtopmd                  2532/udp  # OVTOPMD<BR>
snifferserver            2533/tcp  # SnifferServer<BR>
snifferserver            2533/udp  # SnifferServer<BR>
combox-web-acc           2534/tcp  # Combox Web Access<BR>
combox-web-acc           2534/udp  # Combox Web Access<BR>
mdhcp/madcap             2535/tcp  # MDHCP<BR>, madcap<br><br>madcap<br>
mdhcp/madcap             2535/udp  # MDHCP<BR>, madcap<br><br>madcap<br>
btpp2audctr1             2536/tcp  # btpp2audctrl<BR>
btpp2audctr1             2536/udp  # btpp2audctrl<BR>
upgrade                  2537/tcp  # Upgrade Protocol<BR>
upgrade                  2537/udp  # Upgrade Protocol<BR>
vnwk-prapi               2538/tcp  # vnwk-prapi<BR>
vnwk-prapi               2538/udp  # vnwk-prapi<BR>
vsiadmin                 2539/tcp  # VSI Admin<BR>
vsiadmin                 2539/udp  # VSI Admin<BR>
lonworks                 2540/tcp  # LonWorks<BR>
lonworks                 2540/udp  # LonWorks<BR>
lonworks2                2541/tcp  # LonWorks2<BR>
lonworks2                2541/udp  # LonWorks2<BR>
davinci                  2542/tcp  # DaVinci<BR>
davinci                  2542/udp  # DaVinci<BR>
reftek                   2543/tcp  # REFTEK<BR>
reftek                   2543/udp  # REFTEK<BR>
novell-zen/novell-zen     2544/tcp  # Novell ZEN<BR>, novell-zen<br><br>novell zen<br>
novell-zen               2544/udp  # Novell ZEN<BR>
sis-emt                  2545/tcp  # sis-emt<BR>
sis-emt                  2545/udp  # sis-emt<BR>
vytalvaultbrtp           2546/tcp  # vytalvaultbrtp<BR>
vytalvaultbrtp           2546/udp  # vytalvaultbrtp<BR>
vytalvaultvsmp           2547/tcp  # vytalvaultvsmp<BR>
vytalvaultvsmp           2547/udp  # vytalvaultvsmp<BR>
vytalvaultpipe           2548/tcp  # vytalvaultpipe<BR>
vytalvaultpipe           2548/udp  # vytalvaultpipe<BR>
ipass                    2549/tcp  # IPASS<BR>
ipass                    2549/udp  # IPASS<BR>
ads                      2550/tcp  # ADS<BR>
ads                      2550/udp  # ADS<BR>
isg-uda-server           2551/tcp  # ISG UDA Server<BR>
isg-uda-server           2551/udp  # ISG UDA Server<BR>
call-logging             2552/tcp  # Call Logging<BR>
call-logging             2552/udp  # Call Logging<BR>
efidiningport            2553/tcp  # efidiningport<BR>
efidiningport            2553/udp  # efidiningport<BR>
vcnet-link-v10           2554/tcp  # Vcnet-Link v10<BR>
vcnet-link-v10           2554/udp  # Vcnet-Link v10<BR>
compaq-wcp               2555/tcp  # Compaq WCP<BR>
compaq-wcp               2555/udp  # Compaq WCP<BR>
nicetec-nmsvc            2556/tcp  # nicetec-nmsvc<BR>
nicetec-nmsvc            2556/udp  # nicetec-nmsvc<BR>
nicetec-mgmt             2557/tcp  # nicetec-mgmt<BR>
nicetec-mgmt             2557/udp  # nicetec-mgmt<BR>
pclemultimedia           2558/tcp  # PCLE Multi Media<BR>
pclemultimedia           2558/udp  # PCLE Multi Media<BR>
lstp                     2559/tcp  # LSTP<BR>
lstp                     2559/udp  # LSTP<BR>
labrat                   2560/tcp  # labrat<BR>
labrat                   2560/udp  # labrat<BR>
mosaixcc                 2561/tcp  # MosaixCC<BR>
mosaixcc                 2561/udp  # MosaixCC<BR>
delibo                   2562/tcp  # Delibo<BR>
delibo                   2562/udp  # Delibo<BR>
cti-redwood              2563/tcp  # CTI Redwood<BR>
cti-redwood              2563/udp  # CTI Redwood<BR>
hp-3000-telnet/hp-3000-telnet     2564/tcp  # HP 3000 NS/VT block mode telnet<BR>, hp-3000-telnet<br><br>hp 3000 ns/vt block mode telnet<br>
hp-3000-telnet           2564/udp  # HP 3000 NS/VT block mode telnet<BR>
coord-svr                2565/tcp  # Coordinator Server<BR>
coord-svr                2565/udp  # Coordinator Server<BR>
pcs-pcw                  2566/tcp  # pcs-pcw<BR>
pcs-pcw                  2566/udp  # pcs-pcw<BR>
clp                      2567/tcp  # Cisco Line Protocol<BR>
clp                      2567/udp  # Cisco Line Protocol<BR>
spamtrap                 2568/tcp  # SPAM Trap<BR>
spamtrap                 2568/udp  # SPAM Trap<BR>
sonuscallsig             2569/tcp  # Sonus Call Signal<BR>
sonuscallsig             2569/udp  # Sonus Call Signal<BR>
hs-port                  2570/tcp  # HS Port<BR>
hs-port                  2570/udp  # HS Port<BR>
cecsvc                   2571/tcp  # CECSVC<BR>
cecsvc                   2571/udp  # CECSVC<BR>
ibp                      2572/tcp  # IBP<BR>
ibp                      2572/udp  # IBP<BR>
trustestablish           2573/tcp  # Trust Establish<BR>
trustestablish           2573/udp  # Trust Establish<BR>
blockade-bpsp            2574/tcp  # Blockade BPSP<BR>
blockade-bpsp            2574/udp  # Blockade BPSP<BR>
hl7                      2575/tcp  # HL7<BR>
hl7                      2575/udp  # HL7<BR>
tclprodebugger           2576/tcp  # TCL Pro Debugger<BR>
tclprodebugger           2576/udp  # TCL Pro Debugger<BR>
scipticslsrvr            2577/tcp  # Scriptics Lsrvr<BR>
scipticslsrvr            2577/udp  # Scriptics Lsrvr<BR>
rvs-isdn-dcp             2578/tcp  # RVS ISDN DCP<BR>
rvs-isdn-dcp             2578/udp  # RVS ISDN DCP<BR>
mpfoncl                  2579/tcp  # mpfoncl<BR>
mpfoncl                  2579/udp  # mpfoncl<BR>
tributary                2580/tcp  # Tributary<BR>
tributary                2580/udp  # Tributary<BR>
argis-te                 2581/tcp  # ARGIS TE<BR>
argis-te                 2581/udp  # ARGIS TE<BR>
argis-ds                 2582/tcp  # ARGIS DS<BR>
argis-ds                 2582/udp  # ARGIS DS<BR>
mon                      2583/tcp  # MON<BR>
mon                      2583/udp  # MON<BR>
cyaserv                  2584/tcp  # cyaserv<BR>
cyaserv                  2584/udp  # cyaserv<BR>
netx-server              2585/tcp  # NETX Server<BR>
netx-server              2585/udp  # NETX Server<BR>
netx-agent               2586/tcp  # NETX Agent
netx-agent               2586/udp  # NETX Agent
masc                     2587/tcp  # MASC<BR>
masc                     2587/udp  # MASC<BR>
privilege                2588/tcp  # Privilege<BR>
privilege                2588/udp  # Privilege<BR>
quartus-tcl              2589/tcp  # Quartus TCL<BR>
quartus-tcl              2589/udp  # Quartus TCL<BR>
idotdist                 2590/tcp  # idotdist<BR>
idotdist                 2590/udp  # idotdist<BR>
maytagshuffle            2591/tcp  # Maytag Shuffle<BR>
maytagshuffle            2591/udp  # Maytag Shuffle<BR>
netrek                   2592/tcp  # netrek<BR>
netrek                   2592/udp  # netrek<BR>
mns-mail                 2593/tcp  # MNS Mail Notice Service<BR>
mns-mail                 2593/udp  # MNS Mail Notice Service<BR>
dts                      2594/tcp  # Data Base Server<BR>
dts                      2594/udp  # Data Base Server<BR>
worldfusion1             2595/tcp  # World Fusion 1<BR>
worldfusion1             2595/udp  # World Fusion 1<BR>
worldfusion2             2596/tcp  # World Fusion 2<BR>
worldfusion2             2596/udp  # World Fusion 2<BR>
homesteadglory           2597/tcp  # Homestead Glory<BR>
homesteadglory           2597/udp  # Homestead Glory<BR>
citrixmaclient/citriximaclient     2598/tcp  # Citrix MA Client<BR>, citriximaclient<br><br>citrix ma client<br>
citrixmaclient/citriximaclient     2598/udp  # Citrix MA Client<BR>, citriximaclient<br><br>citrix ma client<br>
meridiandata             2599/tcp  # Meridian Data<BR>
meridiandata             2599/udp  # Meridian Data<BR>
hpstgmgr                 2600/tcp  # HPSTGMGR<BR>
hpstgmgr/hpstgmgr        2600/udp  # HPSTGMGR<BR>, hpstgmgr<br><br>hpstgmgr<br>
discp-client             2601/tcp  # discp client<BR>
discp-client/discp-client     2601/udp  # discp client<BR>, discp-client<br><br>discp client<br>
discp-server             2602/tcp  # discp server<BR>
discp-server/discp-server     2602/udp  # discp server<BR>, discp-server<br><br>discp server<br>
servicemeter             2603/tcp  # Service Meter<BR>
servicemeter/servicemeter     2603/udp  # Service Meter<BR>, servicemeter<br><br>service meter<br>
nsc-ccs                  2604/tcp  # NSC CCS<BR>
nsc-ccs/nsc-ccs          2604/udp  # NSC CCS<BR>, nsc-ccs<br><br>nsc ccs<br>
nsc-posa                 2605/tcp  # NSC POSA<BR>
nsc-posa/nsc-posa        2605/udp  # NSC POSA<BR>, nsc-posa<br><br>nsc posa<br>
netmon                   2606/tcp  # Dell Netmon<BR>
netmon                   2606/udp  # Dell Netmon<BR>
connection               2607/tcp  # Dell Connection<BR>
connection               2607/udp  # Dell Connection<BR>
wag-service              2608/tcp  # Wag Service<BR>
wag-service              2608/udp  # Wag Service<BR>
system-monitor           2609/tcp  # System Monitor<BR>
system-monitor           2609/udp  # System Monitor<BR>
versa-tek                2610/tcp  # VersaTek<BR>
versa-tek                2610/udp  # VersaTek<BR>
linonhead/lionhead       2611/tcp  # LIONHEAD<BR>, lionhead<br><br>lionhead<br>
linonhead/lionhead       2611/udp  # LIONHEAD<BR>, lionhead<br><br>lionhead<br>
qpasa-agent              2612/tcp  # Qpasa Agent<BR>
qpasa-agent              2612/udp  # Qpasa Agent<BR>
smntubootstrap           2613/tcp  # SMNTUBootstrap<BR>
smntubootstrap           2613/udp  # SMNTUBootstrap<BR>
neveroffline             2614/tcp  # Never Offline<BR>
neveroffline             2614/udp  # Never Offline<BR>
firepower                2615/tcp  # Firepower<BR>
firepower                2615/udp  # Firepower<BR>
appswitch-emp            2616/tcp  # appswitch-emp<BR>
appswitch-emp            2616/udp  # appswitch-emp<BR>
cmadmin                  2617/tcp  # Clinical Context Managers<BR>
cmadmin                  2617/udp  # Clinical Context Managers<BR>
priority-e-com           2618/tcp  # Priority E-Com<BR>
priority-e-com           2618/udp  # Priority E-Com<BR>
bruce                    2619/tcp  # bruce<BR>
bruce                    2619/udp  # bruce<BR>
lpsrecommender           2620/tcp  # LPSEecommender<BR>
lpsrecommender           2620/udp  # LPSEecommender<BR>
miles-apart              2621/tcp  # Miles Apart Jukebox Server<BR>
miles-apart              2621/udp  # Miles Apart Jukebox Server<BR>
metricadbc               2622/tcp  # MetricaDBC<BR>
metricadbc               2622/udp  # MetricaDBC<BR>
lmdp                     2623/tcp  # LMDP<BR>
lmdp                     2623/udp  # LMDP<BR>
aria                     2624/tcp  # Aria<BR>
aria                     2624/udp  # Aria<BR>
blwnkl-port              2625/tcp  # Blwnkl Port<BR>
blwnkl-port              2625/udp  # Blwnkl Port<BR>
gbjd816                  2626/tcp  # gbj816<BR>
gbjd816                  2626/udp  # gbj816<BR>
moshebeeri               2627/tcp  # Moshe Beeri<BR>
moshebeeri/moshebeeri     2627/udp  # Moshe Beeri<BR>, moshebeeri<br><br>moshe beeri<br>
dict                     2628/tcp  # DICT<BR>
dict                     2628/udp  # DICT<BR>
sitaraserver             2629/tcp  # Sitara Server<BR>
sitaraserver             2629/udp  # Sitara Server<BR>
sitaramgmt               2630/tcp  # Sitra Management<BR>
sitaramgmt               2630/udp  # Sitra Management<BR>
sitaradir                2631/tcp  # Sitra Dir<BR>
sitaradir                2631/udp  # Sitra Dir<BR>
irdg-post                2632/tcp  # Irdg Post<BR>
irdg-post                2632/udp  # Irdg Post<BR>
interintelli             2633/tcp  # InterIntelli<BR>
interintelli             2633/udp  # InterIntelli<BR>
pk-electronics           2634/tcp  # PK Electronics<BR>
pk-electronics           2634/udp  # PK Electronics<BR>
backburner               2635/tcp  # Back Burner<BR>
backburner               2635/udp  # Back Burner<BR>
solve                    2636/tcp  # Solve<BR>
solve                    2636/udp  # Solve<BR>
imdocsvc                 2637/tcp  # Import Document Service<BR>
imdocsvc                 2637/udp  # Import Document Service<BR>
sybaseanywhere           2638/tcp  # Sybase Anywhere<BR>
sybaseanywhere           2638/udp  # Sybase Anywhere<BR>
aminet                   2639/tcp  # AMInet<BR>
aminet                   2639/udp  # AMInet<BR>
sai_sentlm               2640/tcp  # Sabbagh Associates License Manager<BR>
sai_sentlm               2640/udp  # Sabbagh Associates License Manager<BR>
hdl-srv                  2641/tcp  # HDL Server<BR>
hdl-srv                  2641/udp  # HDL Server<BR>
tragic                   2642/tcp  # Tragic<BR>
tragic                   2642/udp  # Tragic<BR>
gte-samp                 2643/tcp  # GTE-SAMP<BR>
gte-samp                 2643/udp  # GTE-SAMP<BR>
travsoft-ipx-t           2644/tcp  # Travsoft IPX Tunnel<BR>
travsoft-ipx-t           2644/udp  # Travsoft IPX Tunnel<BR>
novell-ipx-cmd           2645/tcp  # Novell IPX CMD<BR>
novell-ipx-cmd           2645/udp  # Novell IPX CMD<BR>
and-lm                   2646/tcp  # AND License Manager<BR>
and-lm/and-lm            2646/udp  # AND License Manager<BR>, and-lm<br><br>and license manager<br>
syncserver               2647/tcp  # SyncServer<BR>
syncserver               2647/udp  # SyncServer<BR>
upsnotifyprot            2648/tcp  # Upsnotifyprot<BR>
upsnotifyprot            2648/udp  # Upsnotifyprot<BR>
vpsipport                2649/tcp  # VPSIPPORT<BR>
vpsipport                2649/udp  # VPSIPPORT<BR>
eristwoguns              2650/tcp  # eristwoguns<BR>
eristwoguns              2650/udp  # eristwoguns<BR>
ebinsite                 2651/tcp  # EBInSite<BR>
ebinsite                 2651/udp  # EBInSite<BR>
interpathpanel           2652/tcp  # InterPathPanel<BR>
interpathpanel           2652/udp  # InterPathPanel<BR>
sonus                    2653/tcp  # Sonus<BR>
sonus                    2653/udp  # Sonus<BR>
corel_vncadmin           2654/tcp  # Corel VNC Admin<BR>
corel_vncadmin           2654/udp  # Corel VNC Admin<BR>
unglue                   2655/tcp  # Unix Nt Glue<BR>
unglue                   2655/udp  # Unix Nt Glue<BR>
kana                     2656/tcp  # Kana<BR>
kana                     2656/udp  # Kana<BR>
sns-dispatcher           2657/tcp  # SNS Dispatcher<BR>
sns-dispatcher           2657/udp  # SNS Dispatcher<BR>
sns-admin                2658/tcp  # SNS Admin<BR>
sns-admin                2658/udp  # SNS Admin<BR>
sns-query                2659/tcp  # SNS Query<BR>
sns-query                2659/udp  # SNS Query<BR>
gcmonitor                2660/tcp  # GC Monitor<BR>
gcmonitor                2660/udp  # GC Monitor<BR>
olhost                   2661/tcp  # OLHOST<BR>
olhost                   2661/udp  # OLHOST<BR>
bintec-capi              2662/tcp  # BinTec-CAPI<BR>
bintec-capi              2662/udp  # BinTec-CAPI<BR>
bintec-tapi              2663/tcp  # BinTec-TAPI<BR>
bintec-tapi              2663/udp  # BinTec-TAPI<BR>
command-mq-gm            2664/tcp  # Command MQ GM<BR>
command-mq-gm            2664/udp  # Command MQ GM<BR>
command-mq-pm            2665/tcp  # Command MQ PM<BR>
command-mq-pm            2665/udp  # Command MQ PM<BR>
extensis                 2666/tcp  # Extensis<BR>
extensis                 2666/udp  # Extensis<BR>
alarm-clock-s            2667/tcp  # Alarm Clock Server<BR>
alarm-clock-s            2667/udp  # Alarm Clock Server<BR>
alarm-clock-c            2668/tcp  # Alarm Clock Client<BR>
alarm-clock-c            2668/udp  # Alarm Clock Client<BR>
toad                     2669/tcp  # TOAD<BR>
toad                     2669/udp  # TOAD<BR>
tve-announce             2670/tcp  # TVE Announce<BR>
tve-announce             2670/udp  # TVE Announce<BR>
newlixreg                2671/tcp  # newlixreg<BR>
newlixreg                2671/udp  # newlixreg<BR>
nhserver                 2672/tcp  # nhserver<BR>
nhserver                 2672/udp  # nhserver<BR>
firstcall42              2673/tcp  # First Call 42<BR>
firstcall42              2673/udp  # First Call 42<BR>
ewnn                     2674/tcp  # ewnn<BR>
ewnn                     2674/udp  # ewnn<BR>
ttc-etap                 2675/tcp  # TTC ETAP<BR>
ttc-etap                 2675/udp  # TTC ETAP<BR>
simslink                 2676/tcp  # SIMSLink<BR>
simslink                 2676/udp  # SIMSLink<BR>
gadgetgate1way           2677/tcp  # Gadget Gate 1 Way<BR>
gadgetgate1way           2677/udp  # Gadget Gate 1 Way<BR>
gadgetgate2way           2678/tcp  # Gadget Gate 2 Way<BR>
gadgetgate2way           2678/udp  # Gadget Gate 2 Way<BR>
syncserverssl            2679/tcp  # Sync Server SSL<BR>
syncserverssl            2679/udp  # Sync Server SSL<BR>
pxc-sapxom               2680/tcp  # pxc-sapxom<BR>
pxc-sapxom               2680/udp  # pxc-sapxom<BR>
mpnjsomb                 2681/tcp  # mpnjsomb<BR>
mpnjsomb                 2681/udp  # mpnjsomb<BR>
srsp                     2682/tcp  # SRSP<BR>
srsp                     2682/udp  # SRSP<BR>
ncdloadbalance           2683/tcp  # NCDLoadBalance<BR>
ncdloadbalance           2683/udp  # NCDLoadBalance<BR>
mpnjsosv                 2684/tcp  # mpnjsosv<BR>
mpnjsosv                 2684/udp  # mpnjsosv<BR>
mpnjsoc1/mpnjsocl        2685/tcp  # mpnjsoc1<BR>, mpnjsocl<br><br>mpnjsocl<br>
mpnjsoc1/mpnjsocl        2685/udp  # mpnjsoc1<BR>, mpnjsocl<br><br>mpnjsocl<br>
mpnjsomg                 2686/tcp  # mpnjsomg<BR>
mpnjsomg                 2686/udp  # mpnjsomg<BR>
pq-lic-mgmt              2687/tcp  # pq-lic-mgmt<BR>
pq-lic-mgmt              2687/udp  # pq-lic-mgmt<BR>
md-cg-http               2688/tcp  # md-cf-http<BR>
md-cg-http               2688/udp  # md-cf-http<BR>
fastlynx                 2689/tcp  # FastLynx<BR>
fastlynx                 2689/udp  # FastLynx<BR>
hp-nnm-data              2690/tcp  # HP NNM Embedded Database<BR>
hp-nnm-data              2690/udp  # HP NNM Embedded Database<BR>
itinternet               2691/tcp  # IT Internet<BR>
itinternet               2691/udp  # IT Internet<BR>
admins-lms               2692/tcp  # Admins LMS<BR>
admins-lms               2692/udp  # Admins LMS<BR>
berarc-http/belarc-http     2693/tcp  # belarc-http<BR>, belarc-http<br><br>belarc-http<br>
berarc-http/belarc-http     2693/udp  # belarc-http<BR>, belarc-http<br><br>belarc-http<br>
pwrsevent                2694/tcp  # pwrsevent<BR>
pwrsevent                2694/udp  # pwrsevent<BR>
vspread                  2695/tcp  # VSPREAD<BR>
vspread                  2695/udp  # VSPREAD<BR>
unifyadmin               2696/tcp  # Unify Admin<BR>
unifyadmin               2696/udp  # Unify Admin<BR>
oce-snmp-trap            2697/tcp  # Oce SNMP Trap Port<BR>
oce-snmp-trap            2697/udp  # Oce SNMP Trap Port<BR>
mck-ivpip                2698/tcp  # MCK-IVPIP<BR>
mck-ivpip                2698/udp  # MCK-IVPIP<BR>
csoft-plusclnt           2699/tcp  # Csoft Plus Client<BR>
csoft-plusclnt           2699/udp  # Csoft Plus Client<BR>
tqdata                   2700/tcp  # tqdata<BR>
tqdata                   2700/udp  # tqdata<BR>
sms-rcinfo               2701/tcp  # SMS RCINFO<BR>
sms-rcinfo               2701/udp  # SMS RCINFO<BR>
sms-xfer                 2702/tcp  # SMS XFER<BR>
sms-xfer                 2702/udp  # SMS XFER<BR>
sms-chat                 2703/tcp  # SMS CHAT<BR>
sms-chat                 2703/udp  # SMS CHAT<BR>
sms-remctrl              2704/tcp  # SMS REMCTRL<BR>
sms-remctrl              2704/udp  # SMS REMCTRL<BR>
sds-admin                2705/tcp  # SDS Admin<BR>
sds-admin                2705/udp  # SDS Admin<BR>
ncdmirroring             2706/tcp  # NCD Mirroring<BR>
ncdmirroring             2706/udp  # NCD Mirroring<BR>
emcsymapiport            2707/tcp  # EMCSYMAPIPORT<BR>
emcsymapiport            2707/udp  # EMCSYMAPIPORT<BR>
banyan-net               2708/tcp  # Banyan-Net<BR>
banyan-net               2708/udp  # Banyan-Net<BR>
supermon                 2709/tcp  # Supermon<BR>
supermon                 2709/udp  # Supermon<BR>
sso-service              2710/tcp  # SSO Service<BR>
sso-service              2710/udp  # SSO Service<BR>
sso-control              2711/tcp  # SSO Control<BR>
sso-control              2711/udp  # SSO Control<BR>
aocp                     2712/tcp  # Axapta Object Comm Protocol<BR>
aocp                     2712/udp  # Axapta Object Comm Protocol<BR>
raven1                   2713/tcp  # Raven-1<BR>
raven1                   2713/udp  # Raven-1<BR>
raven2/raven2            2714/tcp  # Raven-2<BR>, raven2<br><br>raven2<br>
raven2                   2714/udp  # Raven-2<BR>
hpstgmgr2                2715/tcp  # HPSTGMGR-2<BR>
hpstgmgr2                2715/udp  # HPSTGMGR-2<BR>
inova-ip-disco           2716/tcp  # Inova IP Disco<BR>
inova-ip-disco           2716/udp  # Inova IP Disco<BR>
pn-requester             2717/tcp  # PN REQUESTER<BR>
pn-requester             2717/udp  # PN REQUESTER<BR>
pn-requester2            2718/tcp  # PN REQUESTER 2<BR>
pn-requester2            2718/udp  # PN REQUESTER 2<BR>
scan-change              2719/tcp  # Scan &amp; Change<BR>
scan-change              2719/udp  # Scan &amp; Change<BR>
wkars                    2720/tcp  # wkars<BR>
wkars                    2720/udp  # wkars<BR>
smart-diagnose           2721/tcp  # Smart Diagnose<BR>
smart-diagnose           2721/udp  # Smart Diagnose<BR>
proactivesrvr            2722/tcp  # Proactive Server<BR>
proactivesrvr            2722/udp  # Proactive Server<BR>
watchdognt               2723/tcp  # WatchDog NT<BR>
watchdognt               2723/udp  # WatchDog NT<BR>
qotps                    2724/tcp  # qotps<BR>
qotps                    2724/udp  # qotps<BR>
msolap-ptp2              2725/tcp  # MSOLAP PTP2<BR>
msolap-ptp2              2725/udp  # MSOLAP PTP2<BR>
tams                     2726/tcp  # TAMS<BR>
tams                     2726/udp  # TAMS<BR>
mgcp-callagent           2727/tcp  # Media Gateway Control Protocol Call Agent<BR>
mgcp-callagent           2727/udp  # Media Gateway Control Protocol Call Agent<BR>
sqdr                     2728/tcp  # SQDR<BR>
sqdr                     2728/udp  # SQDR<BR>
tcim-control             2729/tcp  # TCIM Control<BR>
tcim-control             2729/udp  # TCIM Control<BR>
nec-raidplus             2730/tcp  # NEC RaidPlus<BR>
nec-raidplus             2730/udp  # NEC RaidPlus<BR>
netdragon-msngr          2731/tcp  # NetDragon Messanger<BR>
netdragon-msngr          2731/udp  # NetDragon Messanger<BR>
g5m                      2732/tcp  # G5M<BR>
g5m                      2732/udp  # G5M<BR>
signet-ctf               2733/tcp  # Signet CTF<BR>
signet-ctf               2733/udp  # Signet CTF<BR>
ccs-software             2734/tcp  # CCS Software<BR>
ccs-software             2734/udp  # CCS Software<BR>
monitorconsole           2735/tcp  # Monitor Console<BR>
monitorconsole           2735/udp  # Monitor Console<BR>
radwiz-nms-srv           2736/tcp  # RADWIZ NMS SRV<BR>
radwiz-nms-srv           2736/udp  # RADWIZ NMS SRV<BR>
srp-feedback             2737/tcp  # SRP Feedback<BR>
srp-feedback             2737/udp  # SRP Feedback<BR>
ndl-tcp-ois-gw           2738/tcp  # NDL TCP-OSI Gateway<BR>
ndl-tcp-ois-gw           2738/udp  # NDL TCP-OSI Gateway<BR>
tn-timing                2739/tcp  # TN Timing<BR>
tn-timing                2739/udp  # TN Timing<BR>
alarm                    2740/tcp  # Alarm<BR>
alarm                    2740/udp  # Alarm<BR>
tsb                      2741/tcp  # TSB<BR>
tsb                      2741/udp  # TSB<BR>
tsb2                     2742/tcp  # TSB2<BR>
tsb2                     2742/udp  # TSB2<BR>
murx                     2743/tcp  # murx<BR>
murx                     2743/udp  # murx<BR>
honyaku                  2744/tcp  # honyaku<BR>
honyaku                  2744/udp  # honyaku<BR>
urbisnet                 2745/tcp  # URBISNET<BR>
urbisnet                 2745/udp  # URBISNET<BR>
cpudpencap               2746/tcp  # CPUDPENCAP<BR>
cpudpencap               2746/udp  # CPUDPENCAP<BR>
fjippol-swrly            2747/tcp  # fjippol-swrly<BR>
fjippol-swrly            2747/udp  # fjippol-swrly<BR>
fjippol-polsrv/fjippol-polsvr     2748/tcp  # fjippol-polsrv<BR>, fjippol-polsvr<br><br><br>
fjippol-polsrv/fjippol-polsvr     2748/udp  # fjippol-polsrv<BR>, fjippol-polsvr<br><br><br>
fjippol-cnsl             2749/tcp  # fjippol-cnsl<BR>
fjippol-cnsl             2749/udp  # fjippol-cnsl<BR>
fjippol-port1            2750/tcp  # fjippol-port1<BR>
fjippol-port1            2750/udp  # fjippol-port1<BR>
fjippol-port2            2751/tcp  # fjippol-port2<BR>
fjippol-port2            2751/udp  # fjippol-port2<BR>
rsisysaccess             2752/tcp  # RSISYS ACCESS<BR>
rsisysaccess             2752/udp  # RSISYS ACCESS<BR>
de-spot                  2753/tcp  # de-spot<BR>
de-spot                  2753/udp  # de-spot<BR>
apollo-cc                2754/tcp  # APOLLO CC<BR>
apollo-cc                2754/udp  # APOLLO CC<BR>
expresspay               2755/tcp  # Express Pay<BR>
expresspay               2755/udp  # Express Pay<BR>
simplement-tie           2756/tcp  # simplement-tie<BR>
simplement-tie           2756/udp  # simplement-tie<BR>
cnrp                     2757/tcp  # CNRP<BR>
cnrp                     2757/udp  # CNRP<BR>
apollo-status            2758/tcp  # APOLLO Status<BR>
apollo-status            2758/udp  # APOLLO Status<BR>
apollo-GMS               2759/tcp  # APOLLO GMS<BR>
apollo-GMS               2759/udp  # APOLLO GMS<BR>
sabams                   2760/tcp  # Saba MS<BR>
sabams                   2760/udp  # Saba MS<BR>
dicom-iscl               2761/tcp  # DICOM ISCL<BR>
dicom-iscl               2761/udp  # DICOM ISCL<BR>
dicom-tls                2762/tcp  # DICOM TLS<BR>
dicom-tls                2762/udp  # DICOM TLS<BR>
desktop-dna              2763/tcp  # Desktop DNA<BR>
desktop-dna              2763/udp  # Desktop DNA<BR>
data-insurance           2764/tcp  # Data Insurance<BR>
data-insurance           2764/udp  # Data Insurance<BR>
gip-audup/qip-audup      2765/tcp  # qip-audup<BR>, qip-audup<br><br>qip-audup<br>
gip-audup/qip-audup      2765/udp  # qip-audup<BR>, qip-audup<br><br>qip-audup<br>
listen/compaq-scp        2766/tcp  # listen<BR><br> Similar to port 1025/listener, but with higher security concerns. <BR> , Compaq SCP<BR>
listen/compaq-scp/compaq-scp     2766/udp  # listen<BR><br> Similar to port 1025/listener, but with higher security concerns. <BR> , Compaq SCP<BR>, compaq-scp<br><br>compaq scp<br>
uadtc                    2767/tcp  # UADTC<BR>
uadtc                    2767/udp  # UADTC<BR>
uacs                     2768/tcp  # UACS<BR>
uacs                     2768/udp  # UACS<BR>
singlept-mvs             2769/tcp  # Single Point MVS<BR>
singlept-mvs             2769/udp  # Single Point MVS<BR>
veronica                 2770/tcp  # Veronica<BR>
veronica                 2770/udp  # Veronica<BR>
vergencecm               2771/tcp  # Vergence CM<BR>
vergencecm               2771/udp  # Vergence CM<BR>
auris                    2772/tcp  # auris<BR>
auris                    2772/udp  # auris<BR>
pcbakcup1                2773/tcp  # PC Backup 1<BR>
pcbakcup1                2773/udp  # PC Backup 1<BR>
pcbakcup2                2774/tcp  # PC Backup 2<BR>
pcbakcup2                2774/udp  # PC Backup 2<BR>
smpp                     2775/tcp  # SMPP<BR>
smpp                     2775/udp  # SMPP<BR>
ridgeway1                2776/tcp  # Ridgeway Systems &amp; Software<BR>
ridgeway1                2776/udp  # Ridgeway Systems &amp; Software<BR>
ridgeway2                2777/tcp  # Ridgeway Systems &amp; Software<BR>
ridgeway2                2777/udp  # Ridgeway Systems &amp; Software<BR>
gwen-sonya               2778/tcp  # Gwen-Sonya<BR>
gwen-sonya               2778/udp  # Gwen-Sonya<BR>
lbc-sync                 2779/tcp  # LBC Sync<BR>
lbc-sync                 2779/udp  # LBC Sync<BR>
lbc-control              2780/tcp  # LBC Control<BR>
lbc-control              2780/udp  # LBC Control<BR>
whosells                 2781/tcp  # whosells<BR>
whosells                 2781/udp  # whosells<BR>
everydayrc               2782/tcp  # everydayrc<BR>
everydayrc               2782/udp  # everydayrc<BR>
aises                    2783/tcp  # AISES<BR>
aises                    2783/udp  # AISES<BR>
www-dev                  2784/tcp  # world wide web - development<BR>
www-dev                  2784/udp  # world wide web - development<BR>
aic-np                   2785/tcp  # aic-np<BR>
aic-np                   2785/udp  # aic-np<BR>
aic-oncrpc               2786/tcp  # aic-oncrpc - Destiny MCD database<BR>
aic-oncrpc               2786/udp  # aic-oncrpc - Destiny MCD database<BR>
piccolo                  2787/tcp  # piccolo - Cornerstone Software<BR>
piccolo                  2787/udp  # piccolo - Cornerstone Software<BR>
fryeserv                 2788/tcp  # NetWare NLM - Seagate Software<BR>
fryeserv                 2788/udp  # NetWare NLM - Seagate Software<BR>
media-agent              2789/tcp  # Media Agent<BR>
media-agent              2789/udp  # Media Agent<BR>
plgproxy                 2790/tcp  # PLG Proxy<BR>
plgproxy                 2790/udp  # PLG Proxy<BR>
mtport-regist            2791/tcp  # MT Port Registrator<BR>
mtport-regist            2791/udp  # MT Port Registrator<BR>
f5-globalsite            2792/tcp  # f5-globalsite<BR>
f5-globalsite            2792/udp  # f5-globalsite<BR>
initlsmsad               2793/tcp  # initlsmsad<BR>
initlsmsad               2793/udp  # initlsmsad<BR>
aaftp                    2794/tcp  # aaftp<BR>
aaftp                    2794/udp  # aaftp<BR>
livestats                2795/tcp  # LiveStats<BR>
livestats                2795/udp  # LiveStats<BR>
ac-tech                  2796/tcp  # ac-tech<BR>
ac-tech                  2796/udp  # ac-tech<BR>
esp-encap                2797/tcp  # esp-encap<BR>
esp-encap                2797/udp  # esp-encap<BR>
tmesis-upshot            2798/tcp  # TMESIS-UPShot tcp/udp<BR>
tmesis-upshot            2798/udp  # TMESIS-UPShot tcp/udp<BR>
icon-discover            2799/tcp  # ICON Discover<BR>
icon-discover            2799/udp  # ICON Discover<BR>
acc-raid                 2800/tcp  # ACC RAID<BR>
acc-raid                 2800/udp  # ACC RAID<BR>
igcp                     2801/tcp  # IGCP<BR>
igcp                     2801/udp  # IGCP<BR>
veritas-tcp1             2802/tcp  # Veritas TCP1<BR>
veritas-udp1             2802/udp  # Veritas UDP1<BR>
btprjctrl                2803/tcp  # btprjctrl<BR>
btprjctrl                2803/udp  # btprjctrl<BR>
telexis-vtu              2804/tcp  # Telexis VTU<BR>
telexis-vtu              2804/udp  # Telexis VTU<BR>
wta-wsp-s                2805/tcp  # WTA WSP-S<BR>
wta-wsp-s                2805/udp  # WTA WSP-S<BR>
cspuni                   2806/tcp  # cspuni<BR>
cspuni                   2806/udp  # cspuni<BR>
cspmulti                 2807/tcp  # cspmulti<BR>
cspmulti                 2807/udp  # cspmulti<BR>
j-lan-p                  2808/tcp  # J-LAN-P<BR>
j-lan-p                  2808/udp  # J-LAN-P<BR>
corbaloc                 2809/tcp  # CORBA LOC<BR>
corbaloc                 2809/udp  # CORBA LOC<BR>
netsteward               2810/tcp  # Active Net Steward<BR>
netsteward               2810/udp  # Active Net Steward<BR>
gsiftp                   2811/tcp  # GSI FTP<BR>
gsiftp                   2811/udp  # GSI FTP<BR>
atmtcp                   2812/tcp  # atmtcp<BR>
atmtcp                   2812/udp  # atmtcp<BR>
llm-pass                 2813/tcp  # llm-pass<BR>
llm-pass                 2813/udp  # llm-pass<BR>
llm-csv                  2814/tcp  # llm-csv<BR>
llm-csv                  2814/udp  # llm-csv<BR>
lbc-measure              2815/tcp  # LBC Measurement<BR>
lbc-measure              2815/udp  # LBC Measurement<BR>
lbc-watchdog             2816/tcp  # LBC Watchdog<BR>
lbc-watchdog             2816/udp  # LBC Watchdog<BR>
nmsigport                2817/tcp  # NMSig Port<BR>
nmsigport                2817/udp  # NMSig Port<BR>
rmlnk                    2818/tcp  # rmlnk<BR>
rmlnk                    2818/udp  # rmlnk<BR>
fc-faultnotify           2819/tcp  # FC Fault Notification<BR>
fc-faultnotify           2819/udp  # FC Fault Notification<BR>
univision                2820/tcp  # UniVision<BR>
univision                2820/udp  # UniVision<BR>
vml-dms                  2821/tcp  # vml-dms<BR>
vml-dms                  2821/udp  # vml-dms<BR>
ka0wuc                   2822/tcp  # ka0wuc<BR>
ka0wuc                   2822/udp  # ka0wuc<BR>
cqg-netlan               2823/tcp  # CQG Net/LAN<BR>
cqg-netlan               2823/udp  # CQG Net/LAN<BR>
slc-systemlog            2826/tcp  # slc systemlog<BR>
slc-systemlog            2826/udp  # slc systemlog<BR>
slc-strlrloops/slc-ctrlrloops     2827/tcp  # slc ctrlrloops<BR>, slc-ctrlrloops<br><br>slc ctrlrloops<br>
slc-strlrloops/slc-ctrlrloops     2827/udp  # slc ctrlrloops<BR>, slc-ctrlrloops<br><br>slc ctrlrloops<br>
itm-lm                   2828/tcp  # ITM License Manager<BR>
itm-lm                   2828/udp  # ITM License Manager<BR>
silkp1                   2829/tcp  # sildp1<BR>
silkp1                   2829/udp  # sildp1<BR>
silkp2                   2830/tcp  # sildp2<BR>
silkp2                   2830/udp  # sildp2<BR>
silkp3                   2831/tcp  # sildp3<BR>
silkp3                   2831/udp  # sildp3<BR>
silkp4                   2832/tcp  # sildp4<BR>
silkp4                   2832/udp  # sildp4<BR>
glishd                   2833/tcp  # glishd<BR>
glishd                   2833/udp  # glishd<BR>
evtp                     2834/tcp  # EVTP<BR>
evtp                     2834/udp  # EVTP<BR>
evtp-data                2835/tcp  # EVTP-Data<BR>
evtp-data                2835/udp  # EVTP-Data<BR>
catalyst                 2836/tcp  # catalyst<BR>
catalyst                 2836/udp  # catalyst<BR>
repliweb                 2837/tcp  # Repliweb<BR>
repliweb                 2837/udp  # Repliweb<BR>
starbot                  2838/tcp  # Starbot<BR>
starbot                  2838/udp  # Starbot<BR>
nmsigport                2839/tcp  # NMSigPort<BR>
nmsigport                2839/udp  # NMSigPort<BR>
13-exprt/l3-exprt        2840/tcp  # 13-exprt<BR>, l3-exprt<br><br>l3-exprt<br>
13-exprt/l3-exprt        2840/udp  # 13-exprt<BR>, l3-exprt<br><br>l3-exprt<br>
13-ranger/l3-ranger      2841/tcp  # 13-ranger<BR>, l3-ranger<br><br>l3-ranger<br>
13-ranger/l3-ranger      2841/udp  # 13-ranger<BR>, l3-ranger<br><br>l3-ranger<br>
13-hawk/l3-hawk          2842/tcp  # 13-hawk<BR>, l3-hawk<br><br>l3-hawk<br>
13-hawk/l3-hawk          2842/udp  # 13-hawk<BR>, l3-hawk<br><br>l3-hawk<br>
pdnet                    2843/tcp  # PDnet<BR>
pdnet                    2843/udp  # PDnet<BR>
bpcp-poll                2844/tcp  # BPCP POLL<BR>
bpcp-poll                2844/udp  # BPCP POLL<BR>
bpcp-trap                2845/tcp  # BPCP TRAP<BR>
bpcp-trap                2845/udp  # BPCP TRAP<BR>
aimpp-hello              2846/tcp  # AIMPP Hello<BR>
aimpp-hello              2846/udp  # AIMPP Hello<BR>
aimpp-port-req           2847/tcp  # AIMPP Port Req<BR>
aimpp-port-req           2847/udp  # AIMPP Port Req<BR>
amt-blc-port             2848/tcp  # AMT-BLC-PORT<BR>
amt-blc-port             2848/udp  # AMT-BLC-PORT<BR>
fxp                      2849/tcp  # FXP<BR>
fxp                      2849/udp  # FXP<BR>
metaconsole              2850/tcp  # MetaConsole<BR>
metaconsole              2850/udp  # MetaConsole<BR>
webemshttp               2851/tcp  # webemshttp<BR>
webemshttp               2851/udp  # webemshttp<BR>
bears-01                 2852/tcp  # bears-01<BR>
bears-01                 2852/udp  # bears-01<BR>
ispipes                  2853/tcp  # ISPipes<BR>
ispipes                  2853/udp  # ISPipes<BR>
infomover                2854/tcp  # InfoMover<BR>
infomover                2854/udp  # InfoMover<BR>
cesdinv                  2856/tcp  # cesdinv<BR>
cesdinv                  2856/udp  # cesdinv<BR>
simctlp                  2857/tcp  # SimCtIP<BR>
simctlp                  2857/udp  # SimCtIP<BR>
ecnp                     2858/tcp  # ECNP<BR>
ecnp                     2858/udp  # ECNP<BR>
activememory             2859/tcp  # Active Memory<BR>
activememory             2859/udp  # Active Memory<BR>
dialpad-voice1           2860/tcp  # Dialpad Voice 1<BR>
dialpad-voice1           2860/udp  # Dialpad Voice 1<BR>
dialpad-voice2           2861/tcp  # Dialpad Voice 2<BR>
dialpad-voice2           2861/udp  # Dialpad Voice 2<BR>
ttg-protocol             2862/tcp  # TTG Protocol<BR>
ttg-protocol             2862/udp  # TTG Protocol<BR>
sonardata                2863/tcp  # Sonar Data<BR>
sonardata                2863/udp  # Sonar Data<BR>
astromed-main            2864/tcp  # main 5001 cmd<BR>
astromed-main            2864/udp  # main 5001 cmd<BR>
pit-vpn                  2865/tcp  # pit-vpn<BR>
pit-vpn                  2865/udp  # pit-vpn<BR>
lwlistener               2866/tcp  # lwlistener<BR>
lwlistener               2866/udp  # lwlistener<BR>
esps-portal              2867/tcp  # esps-portal<BR>
esps-portal              2867/udp  # esps-portal<BR>
npep-messaging           2868/tcp  # NPEP Messaging<BR>
npep-messaging           2868/udp  # NPEP Messaging<BR>
icslap                   2869/tcp  # ICSLAP<BR>
icslap                   2869/udp  # ICSLAP<BR>
daishi                   2870/tcp  # daishi<BR>
daishi                   2870/udp  # daishi<BR>
msi-selectplay           2871/tcp  # MSI Select Play<BR>
msi-selectplay           2871/udp  # MSI Select Play<BR>
contract                 2872/tcp  # CONTRACT<BR>
contract                 2872/udp  # CONTRACT<BR>
paspar2-zoomin           2873/tcp  # PASPAR2 ZoomIn<BR>
paspar2-zoomin           2873/udp  # PASPAR2 ZoomIn<BR>
dxmessagebase1           2874/tcp  # dxmessagebase1<BR>
dxmessagebase1           2874/udp  # dxmessagebase1<BR>
dxmessagebase2           2875/tcp  # dxmessagebase2<BR>
dxmessagebase2           2875/udp  # dxmessagebase2<BR>
sps-tunnel               2876/tcp  # SPS Tunnel<BR>
sps-tunnel               2876/udp  # SPS Tunnel<BR>
bluelance                2877/tcp  # BLUELANCE<BR>
bluelance                2877/udp  # BLUELANCE<BR>
aap                      2878/tcp  # AAP<BR>
aap                      2878/udp  # AAP<BR>
ucentric-ds              2879/tcp  # ucentric-ds<BR>
ucentric-ds              2879/udp  # ucentric-ds<BR>
synapse                  2880/tcp  # synapse<BR>
synapse                  2880/udp  # synapse<BR>
ndsp                     2881/tcp  # NDSP<BR>
ndsp                     2881/udp  # NDSP<BR>
ndtp                     2882/tcp  # NDTP<BR>
ndtp                     2882/udp  # NDTP<BR>
ndnp                     2883/tcp  # NDNP<BR>
ndnp                     2883/udp  # NDNP<BR>
flashmsg                 2884/tcp  # Flash Msg<BR>
flashmsg                 2884/udp  # Flash Msg<BR>
topflow                  2885/tcp  # TopFlow<BR>
topflow                  2885/udp  # TopFlow<BR>
responselogic            2886/tcp  # RESPONSELOGIC<BR>
responselogic            2886/udp  # RESPONSELOGIC<BR>
aironetddp               2887/tcp  # aironet<BR>
aironetddp               2887/udp  # aironet<BR>
spcsdlobby               2888/tcp  # SPCSDLOBBY<BR>
spcsdlobby               2888/udp  # SPCSDLOBBY<BR>
rsom                     2889/tcp  # RSOM<BR>
rsom                     2889/udp  # RSOM<BR>
cspclmulti               2890/tcp  # CSPCLMULTI<BR>
cspclmulti               2890/udp  # CSPCLMULTI<BR>
cinegrfx-elmd            2891/tcp  # CINEGRFX-ELMD License Manager<BR>
cinegrfx-elmd            2891/udp  # CINEGRFX-ELMD License Manager<BR>
snifferdata              2892/tcp  # SNIFFERDATA<BR>
snifferdata              2892/udp  # SNIFFERDATA<BR>
vseconnector             2893/tcp  # VSECONNECTOR<BR>
vseconnector             2893/udp  # VSECONNECTOR<BR>
abacus-remote            2894/tcp  # ABACUS-REMOTE<BR>
abacus-remote            2894/udp  # ABACUS-REMOTE<BR>
natuslink                2895/tcp  # NATUS LINK<BR>
natuslink                2895/udp  # NATUS LINK<BR>
ecovisiong6-1            2896/tcp  # ECOVISIONG6-1<BR>
ecovisiong6-1            2896/udp  # ECOVISIONG6-1<BR>
citrix-rtmp              2897/tcp  # Citrix RTMP<BR>
citrix-rtmp              2897/udp  # Citrix RTMP<BR>
appliance-cfg            2898/tcp  # APPLIANCE-CFG<BR>
appliance-cfg            2898/udp  # APPLIANCE-CFG<BR>
powergemplus             2899/tcp  # POWERGEMPLUS<BR>
powergemplus             2899/udp  # POWERGEMPLUS<BR>
quicksuite               2900/tcp  # QUICKSUITE<BR>
quicksuite               2900/udp  # QUICKSUITE<BR>
allstorcns               2901/tcp  # ALLSTORNCNS<BR>
allstorcns               2901/udp  # ALLSTORNCNS<BR>
netaspi                  2902/tcp  # NET ASPI<BR>
netaspi                  2902/udp  # NET ASPI<BR>
suitcase                 2903/tcp  # SUITCASE<BR>
suitcase                 2903/udp  # SUITCASE<BR>
m2ua                     2904/tcp  # M2UA<BR>
m2ua                     2904/udp  # M2UA<BR>
m3ua                     2905/tcp  # M3UA<BR>
m3ua                     2905/udp  # M3UA<BR>
caller9                  2906/tcp  # CALLER9<BR>
caller9                  2906/udp  # CALLER9<BR>
webmethods-b2b           2907/tcp  # Web Methods Business-to-Business<BR>
webmethods-b2b           2907/udp  # Web Methods Business-to-Business<BR>
mao                      2908/tcp  # mao<BR>
mao                      2908/udp  # mao<BR>
funk-dialout             2909/tcp  # Funk Dialout<BR>
funk-dialout             2909/udp  # Funk Dialout<BR>
tdaccess                 2910/tcp  # TDAccess<BR>
tdaccess                 2910/udp  # TDAccess<BR>
blockade                 2911/tcp  # Blockade<BR>
blockade                 2911/udp  # Blockade<BR>
epiconl/epicon           2912/tcp  # Epicon<BR>, epicon<br><br>epicon<br>
epiconl/epicon           2912/udp  # Epicon<BR>, epicon<br><br>epicon<br>
boosterware              2913/tcp  # Booster Ware<BR>
boosterware              2913/udp  # Booster Ware<BR>
gamelobby                2914/tcp  # Game Lobby<BR>
gamelobby                2914/udp  # Game Lobby<BR>
tksocket                 2915/tcp  # TK Socket<BR>
tksocket                 2915/udp  # TK Socket<BR>
elvin_server             2916/tcp  # Elvin Server<BR>
elvin_server             2916/udp  # Elvin Server<BR>
elvin_client             2917/tcp  # Elvin Client<BR>
elvin_client             2917/udp  # Elvin Client<BR>
kastenchasepad           2918/tcp  # Kasten Chase Pad<BR>
kastenchasepad           2918/udp  # Kasten Chase Pad<BR>
roboer                   2919/tcp  # ROBOER<BR>
roboer                   2919/udp  # ROBOER<BR>
roboeda                  2920/tcp  # ROBOEDA<BR>
roboeda                  2920/udp  # ROBOEDA<BR>
cesdcdman                2921/tcp  # CESD Contents Delivery Management<BR>
cesdcdman                2921/udp  # CESD Contents Delivery Management<BR>
cesdcdtrn                2922/tcp  # CESD Contents Delivery Data Transfer<BR>
cesdcdtrn                2922/udp  # CESD Contents Delivery Data Transfer<BR>
wta-wsp-wtp-s            2923/tcp  # WTA-WSP-WTP-S<BR>
wta-wsp-wtp-s            2923/udp  # WTA-WSP-WTP-S<BR>
precise-vip              2924/tcp  # PRECISE-VIP<BR>
precise-vip              2924/udp  # PRECISE-VIP<BR>
frp                      2925/tcp  # Firewall Redundancy Protocol<BR>
frp                      2925/udp  # Firewall Redundancy Protocol<BR>
mobile-file-dl           2926/tcp  # MOBILE-FILE-DL<BR>
mobile-file-dl           2926/udp  # MOBILE-FILE-DL<BR>
unimobilectrl            2927/tcp  # UNIMOBILECTRL<BR>
unimobilectrl            2927/udp  # UNIMOBILECTRL<BR>
redstone-cpss            2928/tcp  # REDSTONE-CPSS<BR>
redstone-cpss/redstone-cpss     2928/udp  # REDSTONE-CPSS<BR>, redstone-cpss<br><br>redsonte-cpss<br>
panja-webadmin           2929/tcp  # Panja Web Admin<BR>
panja-webadmin           2929/udp  # Panja Web Admin<BR>
panja-weblinx            2930/tcp  # Panja Web Linx<BR>
panja-weblinx            2930/udp  # Panja Web Linx<BR>
circle-x                 2931/tcp  # Circle-X<BR>
circle-x                 2931/udp  # Circle-X<BR>
incp                     2932/tcp  # INCP<BR>
incp                     2932/udp  # INCP<BR>
4-tieropmgw              2933/tcp  # 4-Tief OPM CW<BR>
4-tieropmgw              2933/udp  # 4-Tief OPM CW<BR>
4-tieropmcli             2934/tcp  # 4-Tier OPM CLI<BR>
4-tieropmcli             2934/udp  # 4-Tier OPM CLI<BR>
qtp                      2935/tcp  # QTP<BR>
qtp                      2935/udp  # QTP<BR>
otpatch                  2936/tcp  # OTPatch<BR>
otpatch                  2936/udp  # OTPatch<BR>
pnaconsult-lm            2937/tcp  # PNA Consult License Manager<BR>
pnaconsult-lm            2937/udp  # PNA Consult License Manager<BR>
sm-pas-1                 2938/tcp  # SM-PAS-1<BR>
sm-pas-1                 2938/udp  # SM-PAS-1<BR>
sm-pas-2                 2939/tcp  # SM-PAS-2<BR>
sm-pas-2                 2939/udp  # SM-PAS-2<BR>
sm-pas-3                 2940/tcp  # SM-PAS-3<BR>
sm-pas-3                 2940/udp  # SM-PAS-3<BR>
sm-pas-4                 2941/tcp  # SM-PAS-4<BR>
sm-pas-4                 2941/udp  # SM-PAS-4<BR>
sm-pas-5                 2942/tcp  # SM-PAS-5<BR>
sm-pas-5                 2942/udp  # SM-PAS-5<BR>
ttnrepository            2943/tcp  # TTN Repository<BR>
ttnrepository            2943/udp  # TTN Repository<BR>
megaco-h248              2944/tcp  # Megaco H248<BR>
megaco-h248              2944/udp  # Megaco H248<BR>
h248-binary              2945/tcp  # H248 Binary<BR>
h248-binary              2945/udp  # H248 Binary<BR>
fjsvmpor                 2946/tcp  # FJSVmpor<BR>
fjsvmpor                 2946/udp  # FJSVmpor<BR>
gpsd                     2947/tcp  # GPSD<BR>
gpsd                     2947/udp  # GPSD<BR>
wap-push                 2948/tcp  # WAP PUSH<BR>
wap-push                 2948/udp  # WAP PUSH<BR>
wap-pushsecure           2949/tcp  # WAP PUSH SECURE<BR>
wap-pushsecure           2949/udp  # WAP PUSH SECURE<BR>
esip                     2950/tcp  # ESIP<BR>
esip                     2950/udp  # ESIP<BR>
ottp                     2951/tcp  # OTTP<BR>
ottp                     2951/udp  # OTTP<BR>
mpfwsas                  2952/tcp  # MPFWSAS<BR>
mpfwsas                  2952/udp  # MPFWSAS<BR>
ovalarmsrv               2953/tcp  # OV Alarm Server<BR>
ovalarmsrv               2953/udp  # OV Alarm Server<BR>
ovalarmsrv-cmd           2954/tcp  # OV Alarm Server - Command<BR>
ovalarmsrv-cmd           2954/udp  # OV Alarm Server - Command<BR>
csnotify                 2955/tcp  # CS Notify<BR>
csnotify                 2955/udp  # CS Notify<BR>
ovrimosdbman             2956/tcp  # OVRIMOSDBMAN<BR>
ovrimosdbman             2956/udp  # OVRIMOSDBMAN<BR>
jmact5                   2957/tcp  # JMACT5<BR>
jmact5                   2957/udp  # JMACT5<BR>
jmact6                   2958/tcp  # JMACT6<BR>
jmact6                   2958/udp  # JMACT6<BR>
rmopagt                  2959/tcp  # RMOPAGT<BR>
rmopagt                  2959/udp  # RMOPAGT<BR>
boldsoft-lm              2961/tcp  # BoldSoft License Manager<BR>
boldsoft-lm              2961/udp  # BoldSoft License Manager<BR>
iph-policy-cli           2962/tcp  # IPH-Policy-CLI<BR>
iph-policy-cli           2962/udp  # IPH-Policy-CLI<BR>
iph-policy-adm           2963/tcp  # IPH-Policy-Admin<BR>
iph-policy-adm           2963/udp  # IPH-Policy-Admin<BR>
bullant-srap             2964/tcp  # Bullant SRP<BR>
bullant-srap             2964/udp  # Bullant SRP<BR>
bullant-rap              2965/tcp  # Bullant RAP<BR>
bullant-rap              2965/udp  # Bullant RAP<BR>
idp-infotriev/idp-infotrieve     2966/tcp  # IDP-INFOTRIEVE<BR>, idp-infotrieve<br><br>idp-infotrieve<br>
idp-infotriev/idp-infotrieve     2966/udp  # IDP-INFOTRIEVE<BR>, idp-infotrieve<br><br>idp-infotrieve<br>
ssc-agent                2967/tcp  # SSC Agent<BR>
ssc-agent                2967/udp  # SSC Agent<BR>
enpp                     2968/tcp  # ENPP<BR>
enpp                     2968/udp  # ENPP<BR>
ESSP                     2969/tcp  # ESSP<BR>
ESSP                     2969/udp  # ESSP<BR>
index-net                2970/tcp  # INDEX-NET<BR>
index-net                2970/udp  # INDEX-NET<BR>
netclip                  2971/tcp  # Net Clip<BR>
netclip                  2971/udp  # Net Clip<BR>
pmsm-webrctl             2972/tcp  # PMSM Webrctl<BR>
pmsm-webrctl             2972/udp  # PMSM Webrctl<BR>
svnetworks               2973/tcp  # SV Networks<BR>
svnetworks               2973/udp  # SV Networks<BR>
signal                   2974/tcp  # Signal<BR>
signal                   2974/udp  # Signal<BR>
fjmpcm                   2975/tcp  # Fujitsu Configuration Mgmt Service<BR>
fjmpcm                   2975/udp  # Fujitsu Configuration Mgmt Service<BR>
cns-srv-port             2976/tcp  # CNS Server Port<BR>
cns-srv-port             2976/udp  # CNS Server Port<BR>
ttc-etap-ns              2977/tcp  # TTCs Enterprise Test Access Protocol - NS<BR>
ttc-etap-ns              2977/udp  # TTCs Enterprise Test Access Protocol - NS<BR>
ttc-etap-ds              2978/tcp  # TTCs Enterprise Test Access Protocol - DS<BR>
ttc-etap-ds              2978/udp  # TTCs Enterprise Test Access Protocol - DS<BR>
h263-video               2979/tcp  # H.263 Video Streaming<BR>
h263-video               2979/udp  # H.263 Video Streaming<BR>
wimd                     2980/tcp  # Instant Messaging Service<BR>
wimd                     2980/udp  # Instant Messaging Service<BR>
mylxamport               2981/tcp  # MYLXAMPORT<BR>
mylxamport               2981/udp  # MYLXAMPORT<BR>
iwb-whiteboard           2982/tcp  # IWB Whiteboard<BR>
iwb-whiteboard           2982/udp  # IWB Whiteboard<BR>
netplan                  2983/tcp  # NetPlan<BR>
netplan                  2983/udp  # NetPlan<BR>
hpidsadmin               2984/tcp  # HP IDS Admin<BR>
hpidsadmin               2984/udp  # HP IDS Admin<BR>
hpidsagent               2985/tcp  # HP IDS Agent<BR>
hpidsagent/hpidsagnet     2985/udp  # HP IDS Agent<BR>, hpidsagnet<br><br>hpidsagent<br>
stonefalls               2986/tcp  # StoneFalls<BR>
stonefalls               2986/udp  # StoneFalls<BR>
identify                 2987/tcp  # Identify<BR>
identify                 2987/udp  # Identify<BR>
classify                 2988/tcp  # Classify<BR>
classify                 2988/udp  # Classify<BR>
zarkov                   2989/tcp  # Zarkov<BR>
zarkov                   2989/udp  # Zarkov<BR>
boscap                   2990/tcp  # BOSCAP<BR>
boscap                   2990/udp  # BOSCAP<BR>
wkstn-mon                2991/tcp  # WKSTN-MON<BR>
wkstn-mon                2991/udp  # WKSTN-MON<BR>
itb301                   2992/tcp  # ITB301<BR>
itb301                   2992/udp  # ITB301<BR>
veritas-vis1             2993/tcp  # Veritas Vis1<BR>
veritas-vis1             2993/udp  # Veritas Vis1<BR>
veritas-vis2             2994/tcp  # Veritas Vis2<BR>
veritas-vis2             2994/udp  # Veritas Vis2<BR>
idrs                     2995/tcp  # IDRS<BR>
idrs                     2995/udp  # IDRS<BR>
vsixml                   2996/tcp  # vsixml<BR>
vsixml                   2996/udp  # vsixml<BR>
rebol                    2997/tcp  # REBOL<BR>
rebol                    2997/udp  # REBOL<BR>
realsecure               2998/tcp  # Real Secure<BR>
realsecure               2998/udp  # Real Secure<BR>
remoteware-un            2999/tcp  # RemoteWare Unassigned<BR>
remoteware-un            2999/udp  # RemoteWare Unassigned<BR>
ntop/remoteware-cl/hbci     3000/tcp  # ntop<BR><br> Web port for ntop, which grabs/stores/analyzes network transfer info and protocol stat's. Defaults to port 3000 with no auth, can be configured to only allow connects from specific IPs. Is also its own web server. <BR> , RemoteWare Client<BR>, HBCI<BR>
remoteware-cl/hbci/hbci     3000/udp  # RemoteWare Client<BR>, HBCI<BR>, hbci<br><br>remoteware client, hbci<br>
nessus-server/redwood-broker     3001/tcp  # Nessus Server<BR>, Redwood Broker<BR>
redwood-broker           3001/udp  # Redwood Broker<BR>
exlm-agent/remoteware-srv     3002/tcp  # EXLM Agent<BR>, RemoteWare Server<BR>
exlm-agent/remoteware-srv     3002/udp  # EXLM Agent<BR>, RemoteWare Server<BR>
cgms                     3003/tcp  # CGMS<BR>
cgms                     3003/udp  # CGMS<BR>
csoftragent              3004/tcp  # Csoft Agent<BR>
csoftragent              3004/udp  # Csoft Agent<BR>
geniuslm                 3005/tcp  # Genius License Manager<BR>
geniuslm/geniuslm        3005/udp  # Genius License Manager<BR>, geniuslm<br><br>genius license manager<br>
ii-admin                 3006/tcp  # Instant Internet Admin<BR>
ii-admin                 3006/udp  # Instant Internet Admin<BR>
lotusmtap                3007/tcp  # LotusMail Tracking Agent Protocol<BR>
lotusmtap                3007/udp  # LotusMail Tracking Agent Protocol<BR>
midnight-tech            3008/tcp  # Midnight Technologies<BR>
midnight-tech            3008/udp  # Midnight Technologies<BR>
pxc-ntfy                 3009/tcp  # PXC-NTFY<BR>
pxc-ntfy                 3009/udp  # PXC-NTFY<BR>
gw                       3010/tcp  # Telerate Workstation<BR>
ping-pong                3010/udp  # Telerate Workstation<BR>
trusted-web              3011/tcp  # Trusted Web<BR>
trusted-web              3011/udp  # Trusted Web<BR>
twsdss                   3012/tcp  # Trusted Web Client<BR>
twsdss                   3012/udp  # Trusted Web Client<BR>
gilatskysurfer           3013/tcp  # Gilat Sky Surfer<BR>
gilatskysurfer           3013/udp  # Gilat Sky Surfer<BR>
broker_service           3014/tcp  # Broker Service<BR>
broker_service           3014/udp  # Broker Service<BR>
nati-dstp                3015/tcp  # NATI DSTP<BR>
nati-dstp                3015/udp  # NATI DSTP<BR>
notify_srvr              3016/tcp  # Notify Server<BR>
notify_srvr              3016/udp  # Notify Server<BR>
event_listener           3017/tcp  # Event Listener<BR>
event_listener           3017/udp  # Event Listener<BR>
srvc_registry            3018/tcp  # Service Registry<BR>
srvc_registry            3018/udp  # Service Registry<BR>
resource_mgr             3019/tcp  # Resource Manager<BR>
resource_mgr             3019/udp  # Resource Manager<BR>
cifs                     3020/tcp  # CIFS<BR>
cifs                     3020/udp  # CIFS<BR>
agriserver               3021/tcp  # AGRI Server<BR>
agriserver               3021/udp  # AGRI Server<BR>
csregagent               3022/tcp  # CSREGAGENT<BR>
csregagent               3022/udp  # CSREGAGENT<BR>
magicnotes               3023/tcp  # magicnotes<BR>
magicnotes               3023/udp  # magicnotes<BR>
nds_sso                  3024/tcp  # NDS_SSO<BR>
nds_sso                  3024/udp  # NDS_SSO<BR>
arepa-raft               3025/tcp  # Arepa Raft<BR>
arepa-raft               3025/udp  # Arepa Raft<BR>
agri-gateway             3026/tcp  # AGRI Gateway<BR>
agri-gateway             3026/udp  # AGRI Gateway<BR>
liebdevmgmt_c            3027/tcp  # LiebDevMgmt_C<BR>
liebdevmgmt_c            3027/udp  # LiebDevMgmt_C<BR>
liebdevmgmt_dm           3028/tcp  # liebdevmgmt_dm<BR>
liebdevmgmt_dm           3028/udp  # liebdevmgmt_dm<BR>
liebdevmgmt_a            3029/tcp  # liebdevmgmt_a<BR>
liebdevmgmt_a            3029/udp  # liebdevmgmt_a<BR>
arepa-cas                3030/tcp  # Arepa Cas<BR>
arepa-cas                3030/udp  # Arepa Cas<BR>
agentvu                  3031/tcp  # Agent VU<BR>
agentvu                  3031/udp  # Agent VU<BR>
redwood-chat             3032/tcp  # Redwood Chat<BR>
redwood-chat             3032/udp  # Redwood Chat<BR>
pdb                      3033/tcp  # PDB<BR>
pdb                      3033/udp  # PDB<BR>
osmosis-aeea             3034/tcp  # Osmosis AEEA<BR>
osmosis-aeea             3034/udp  # Osmosis AEEA<BR>
fjsv-gssagt              3035/tcp  # FJSV gssagt<BR>
fjsv-gssagt              3035/udp  # FJSV gssagt<BR>
hagel-dump               3036/tcp  # Hagel Dump<BR>
hagel-dump               3036/udp  # Hagel Dump<BR>
hp-san-mgmt              3037/tcp  # HP SAN Mgmt<BR>
hp-san-mgmt              3037/udp  # HP SAN Mgmt<BR>
santak-ups               3038/tcp  # Santak UPS<BR>
santak-ups               3038/udp  # Santak UPS<BR>
cogitate                 3039/tcp  # Cogitate, Inc.<BR>
cogitate                 3039/udp  # Cogitate, Inc.<BR>
tomato-springs           3040/tcp  # Tomato Springs<BR>
tomato-springs           3040/udp  # Tomato Springs<BR>
di-traceware             3041/tcp  # DI Traceware<BR>
di-traceware             3041/udp  # DI Traceware<BR>
journee                  3042/tcp  # journee<BR>
journee                  3042/udp  # journee<BR>
brp                      3043/tcp  # BRP<BR>
brp                      3043/udp  # BRP<BR>
responsenet              3045/tcp  # ResponseNet<BR>
responsenet              3045/udp  # ResponseNet<BR>
di-ase                   3046/tcp  # di-ase<BR>
di-ase                   3046/udp  # di-ase<BR>
hlserver                 3047/tcp  # Fast Security HL Server<BR>
hlserver                 3047/udp  # Fast Security HL Server<BR>
pctrader                 3048/tcp  # Sierra Net PC Trader<BR>
pctrader                 3048/udp  # Sierra Net PC Trader<BR>
NSWS                     3049/tcp  # NSWS<BR>
NSWS/nsws                3049/udp  # NSWS<BR>, nsws<br><br>nsws, cryptographic file system (nfs)<br>
gds_db                   3050/tcp  # gds)db<BR>
gds_db                   3050/udp  # gds)db<BR>
galaxy-server            3051/tcp  # Galaxy Server<BR>
galaxy-server            3051/udp  # Galaxy Server<BR>
apcpcns                  3052/tcp  # APCPCNS<BR>
apcpcns                  3052/udp  # APCPCNS<BR>
dsom-server              3053/tcp  # DSOM Server<BR>
dsom-server              3053/udp  # DSOM Server<BR>
amt-cnf-prot             3054/tcp  # AMT CNF PROT<BR>
amt-cnf-prot             3054/udp  # AMT CNF PROT<BR>
policyserver             3055/tcp  # Policy Server<BR>
policyserver             3055/udp  # Policy Server<BR>
cdl-server               3056/tcp  # CDL Server<BR>
cdl-server               3056/udp  # CDL Server<BR>
goahead-fldup            3057/tcp  # GoAhead FldUp<BR>
goahead-fldup            3057/udp  # GoAhead FldUp<BR>
videobeans               3058/tcp  # VideoBeans<BR>
videobeans               3058/udp  # VideoBeans<BR>
qsoft/qsoft              3059/tcp  # QSoft<BR>, qsoft<br><br>qsoft<br>
qsoft                    3059/udp  # QSoft<BR>
interserver              3060/tcp  # interserver<BR>
interserver              3060/udp  # interserver<BR>
cautcpd                  3061/tcp  # cautcpd<BR>
cautcpd                  3061/udp  # cautcpd<BR>
ncacn-ip-tcp/ncacn-ip-tcp     3062/tcp  # NCACN-IP-TCP<BR>, ncacn-ip-tcp<br><br>ncacn-ip-tcp<br>
ncacn-ip-tcp             3062/udp  # ncacn-ip-tcp<br><br>ncacn-ip-tcp<br>
ncadg-ip-udp             3063/tcp  # ncadg-ip-udp<br><br>ncadg-ip-udp<br>
ncacn-ip-udp/ncadg-ip-udp     3063/udp  # NCACN-IP-UDP<BR>, ncadg-ip-udp<br><br>ncadg-ip-udp<br>
slinterbase              3065/tcp  # SlinterBase<BR>
slinterbase              3065/udp  # SlinterBase<BR>
netattachsdmp            3066/tcp  # NETATTACHSDMP<BR>
netattachsdmp            3066/udp  # NETATTACHSDMP<BR>
fjhpjp                   3067/tcp  # FJHPJP<BR>
fjhpjp                   3067/udp  # FJHPJP<BR>
ls3bcast                 3068/tcp  # ls3 Broadcast<BR>
ls3bcast                 3068/udp  # ls3 Broadcast<BR>
ls3                      3069/tcp  # ls3<BR>
ls3                      3069/udp  # ls3<BR>
mgxswitch                3070/tcp  # MGXSwitch<BR>
mgxswitch                3070/udp  # MGXSwitch<BR>
opsec-sam                3071/tcp  # OPSEC SAM<BR>
opsec-sam                3071/udp  # OPSEC SAM<BR>
opsec-lea                3072/tcp  # OPSEC LEA<BR>
opsec-lea                3072/udp  # OPSEC LEA<BR>
opsec-ela                3073/tcp  # OPSEC ELA<BR>
opsec-ela                3073/udp  # OPSEC ELA<BR>
opsec-omi                3074/tcp  # OPSEC OMI<BR>
opsec-omi                3074/udp  # OPSEC OMI<BR>
orbix-locator            3075/tcp  # Orbix 2000 Locator<BR>
orbix-locator            3075/udp  # Orbix 2000 Locator<BR>
orbix-config             3076/tcp  # Orbix 2000 Config<BR>
orbix-config             3076/udp  # Orbix 2000 Config<BR>
orbix-loc-ssl            3077/tcp  # Orbix 2000 Locator SSL<BR>
orbix-loc-ssl            3077/udp  # Orbix 2000 Locator SSL<BR>
orbix-cfg-ssl            3078/tcp  # Orbix-2000 Locator SSL<BR>
orbix-cfg-ssl            3078/udp  # Orbix-2000 Locator SSL<BR>
stm_pproc                3080/tcp  # stm_proc<BR>
stm_pproc                3080/udp  # stm_proc<BR>
tl1-lv                   3081/tcp  # TL1-LC<BR>
tl1-lv                   3081/udp  # TL1-LC<BR>
tl1-raw                  3082/tcp  # TL1-RAW<BR>
tl1-raw                  3082/udp  # TL1-RAW<BR>
tl1-telnet               3083/tcp  # TL1 Telnet<BR>
tl1-telnet               3083/udp  # TL1 Telnet<BR>
cardbox                  3105/tcp  # Cardbox<BR>
cardbox                  3105/udp  # Cardbox<BR>
cardbox-http             3106/tcp  # Cardbox HTTP<BR>
cardbox-http             3106/udp  # Cardbox HTTP<BR>
squid-proxy              3128/tcp  # Squid (Squid Web Proxy Cache)
squid-proxy              3128/udp  # Squid (Squid Web Proxy Cache)
icpv2                    3130/tcp  # ICPv2<BR>
icpv2                    3130/udp  # ICPv2<BR>
netbookmark              3131/tcp  # Net Book Mark<BR>
netbookmark              3131/udp  # Net Book Mark<BR>
vmodem                   3141/tcp  # VMODEM<BR>
vmodem                   3141/udp  # VMODEM<BR>
rdc-wh-eos               3142/tcp  # RDC WH EOS<BR>
rdc-wh-eos               3142/udp  # RDC WH EOS<BR>
seaview                  3143/tcp  # Sea View<BR>
seaview                  3143/udp  # Sea View<BR>
tarantella               3144/tcp  # Tarantella<BR>
tarantella               3144/udp  # Tarantella<BR>
csi-lfap                 3145/tcp  # CSI-LFAP<BR>
csi-lfap                 3145/udp  # CSI-LFAP<BR>
rfio                     3147/tcp  # RFIO<BR>
rfio                     3147/udp  # RFIO<BR>
nm-game-admin            3148/tcp  # NetMike Game Administrator<BR>
nm-game-admin            3148/udp  # NetMike Game Administrator<BR>
nm-game-server           3149/tcp  # NetMike Game Server<BR>
nm-game-server           3149/udp  # NetMike Game Server<BR>
nm-asses-admin           3150/tcp  # NetMike Assessor Administrator<BR>
nm-asses-admin           3150/udp  # NetMike Assessor Administrator<BR>
nm-assessor              3151/tcp  # NetMike Assessor<BR>
nm-assessor              3151/udp  # NetMike Assessor<BR>
mc-brk-srv               3180/tcp  # Millicent Broker Server<BR>
mc-brk-srv               3180/udp  # Millicent Broker Server<BR>
bmcpatrolagent           3181/tcp  # BMC Patrol Agent<BR>
bmcpatrolagent           3181/udp  # BMC Patrol Agent<BR>
bmcpatrolrnvu            3182/tcp  # BMC Patrol Rendezvous<BR>
bmcpatrolrnvu            3182/udp  # BMC Patrol Rendezvous<BR>
necp                     3262/tcp  # NECP<BR>
necp                     3262/udp  # NECP<BR>
ccmail                   3264/tcp  # cc:mail/lotus<BR>
ccmail                   3264/udp  # cc:mail/lotus<BR>
altav-tunnel             3265/tcp  # Altav Tunnel<BR>
altav-tunnel             3265/udp  # Altav Tunnel<BR>
ns-cfg-server            3266/tcp  # NS CFG Server<BR>
ns-cfg-server            3266/udp  # NS CFG Server<BR>
ibm-dial-out             3267/tcp  # IBM Dial Out<BR>
ibm-dial-out             3267/udp  # IBM Dial Out<BR>
msft-gc                  3268/tcp  # Microsoft Global Catalog<BR>
msft-gc                  3268/udp  # Microsoft Global Catalog<BR>
msft-gc-ssl              3269/tcp  # Microsoft Global Catalog w/ LDAP/SSL<BR>
msft-gc-ssl              3269/udp  # Microsoft Global Catalog w/ LDAP/SSL<BR>
verismart                3270/tcp  # Verismart<BR>
verismart                3270/udp  # Verismart<BR>
csoft-prev               3271/tcp  # CSoft Prev Port<BR>
csoft-prev               3271/udp  # CSoft Prev Port<BR>
user-manager             3272/tcp  # Fujitsu User Manager<BR>
user-manager             3272/udp  # Fujitsu User Manager<BR>
sxmp                     3273/tcp  # Simple Experimental Multiplexed Protocol<BR>
sxmp                     3273/udp  # Simple Experimental Multiplexed Protocol<BR>
ordinox-server           3274/tcp  # Ordinox Server<BR>
ordinox-server           3274/udp  # Ordinox Server<BR>
samd                     3275/tcp  # SAMD<BR>
samd                     3275/udp  # SAMD<BR>
maxim-asics              3276/tcp  # Maxim ASICs<BR>
maxim-asics              3276/udp  # Maxim ASICs<BR>
awg-proxy                3277/tcp  # AWG Proxy<BR>
awg-proxy                3277/udp  # AWG Proxy<BR>
lkcmserver               3278/tcp  # LKCM Server<BR>
lkcmserver               3278/udp  # LKCM Server<BR>
admind                   3279/tcp  # admind<BR>
admind                   3279/udp  # admind<BR>
vs-server                3280/tcp  # VS Server<BR>
vs-server                3280/udp  # VS Server<BR>
sysopt                   3281/tcp  # SYSOPT<BR>
sysopt                   3281/udp  # SYSOPT<BR>
datusorb                 3282/tcp  # Datusorb<BR>
datusorb                 3282/udp  # Datusorb<BR>
net-assistant            3283/tcp  # Net Assistant<BR>
net-assistant            3283/udp  # Net Assistant<BR>
4talk                    3284/tcp  # 4Talk<BR>
4talk                    3284/udp  # 4Talk<BR>
plato                    3285/tcp  # Plato<BR>
plato                    3285/udp  # Plato<BR>
e-net                    3286/tcp  # E-Net<BR>
e-net                    3286/udp  # E-Net<BR>
directvdata              3287/tcp  # DIRECTVDATA<BR>
directvdata              3287/udp  # DIRECTVDATA<BR>
cops                     3288/tcp  # COPS<BR>
cops                     3288/udp  # COPS<BR>
enpc                     3289/tcp  # ENPC<BR>
enpc                     3289/udp  # ENPC<BR>
caps-lm                  3290/tcp  # CAPS-LOGISTICS TOOLKIT - LM<BR>
caps-lm                  3290/udp  # CAPS-LOGISTICS TOOLKIT - LM<BR>
sah-lm                   3291/tcp  # S A Holditch &amp; Associates - LM<BR>
sah-lm                   3291/udp  # S A Holditch &amp; Associates - LM<BR>
cart-o-rama              3292/tcp  # Cart O Rama<BR>
cart-o-rama              3292/udp  # Cart O Rama<BR>
fg-fps                   3293/tcp  # fg-fps<BR>
fg-fps                   3293/udp  # fg-fps<BR>
fg-gip                   3294/tcp  # fg-gip<BR>
fg-gip                   3294/udp  # fg-gip<BR>
dyniplookup              3295/tcp  # Dynamic IP Lookup<BR>
dyniplookup              3295/udp  # Dynamic IP Lookup<BR>
rib-slm                  3296/tcp  # Rib License Manager<BR>
rib-slm                  3296/udp  # Rib License Manager<BR>
cytel-lm                 3297/tcp  # Cytel License Manager<BR>
cytel-lm                 3297/udp  # Cytel License Manager<BR>
transview                3298/tcp  # Transview<BR>
transview                3298/udp  # Transview<BR>
pdrncs                   3299/tcp  # pdrncs<BR>
pdrncs                   3299/udp  # pdrncs<BR>
bmcpatrolagent           3300/tcp  # BMC Patrol Agent<BR>
bmcpatrolagent           3300/udp  # BMC Patrol Agent<BR>
bmcpatrolrnvu            3301/tcp  # BMC Patrol Rendezvous<BR>
bmcpatrolrnvu            3301/udp  # BMC Patrol Rendezvous<BR>
mcs-fastmail             3302/tcp  # MCS Fastmail<BR>
mcs-fastmail             3302/udp  # MCS Fastmail<BR>
opsession-clnt           3303/tcp  # OP Session Client<BR>
opsession-clnt           3303/udp  # OP Session Client<BR>
opsession-srvr           3304/tcp  # OP Session Server<BR>
opsession-srvr           3304/udp  # OP Session Server<BR>
odette-ftp               3305/tcp  # ODETTE-FTP<BR>
odette-ftp               3305/udp  # ODETTE-FTP<BR>
mysq1/mysql              3306/tcp  # MySQL<BR>, mysql<br><br>mysql<br>
mysq1/mysql              3306/udp  # MySQL<BR>, mysql<br><br>mysql<br>
opsession-prxy           3307/tcp  # OP Session Proxy<BR>
opsession-prxy           3307/udp  # OP Session Proxy<BR>
tns-server               3308/tcp  # TNS Server<BR>
tns-server               3308/udp  # TNS Server<BR>
tns-adv                  3309/tcp  # TNS ADV<BR>
tns-adv/tns-adv          3309/udp  # TNS ADV<BR>, tns-adv<br><br>tnd adv<br>
dyna-access              3310/tcp  # Dyna Access<BR>
dyna-access              3310/udp  # Dyna Access<BR>
mcns-tel-ret             3311/tcp  # MCNS Tel Ret<BR>
mcns-tel-ret             3311/udp  # MCNS Tel Ret<BR>
appman-server            3312/tcp  # Application Management Server<BR>
appman-server            3312/udp  # Application Management Server<BR>
uorb                     3313/tcp  # Unify Object Broker<BR>
uorb                     3313/udp  # Unify Object Broker<BR>
uohost                   3314/tcp  # Unify Object Host<BR>
uohost                   3314/udp  # Unify Object Host<BR>
cdid                     3315/tcp  # CDID<BR>
cdid                     3315/udp  # CDID<BR>
aicc-cmi                 3316/tcp  # AICC/CMI<BR>
aicc-cmi                 3316/udp  # AICC/CMI<BR>
vsaiport                 3317/tcp  # VSAI PORT<BR>
vsaiport                 3317/udp  # VSAI PORT<BR>
ssrip                    3318/tcp  # Switch to Switch Routing Info Protocol<BR>
ssrip                    3318/udp  # Switch to Switch Routing Info Protocol<BR>
sdt-lmd                  3319/tcp  # SDT License Manager<BR>
sdt-lmd                  3319/udp  # SDT License Manager<BR>
officelink2000           3320/tcp  # Office Link 2000<BR>
officelink2000           3320/udp  # Office Link 2000<BR>
vnsstr                   3321/tcp  # VNSSTR<BR>
vnsstr                   3321/udp  # VNSSTR<BR>
active-net/active-net     3322/tcp  # Active Networks<BR>, active-net<br><br>active networks<br>
active-net               3322/udp  # Active Networks<BR>
active-net/active-net     3323/tcp  # Active Networks<BR>, active-net<br><br>active networks<br>
active-net               3323/udp  # Active Networks<BR>
active-net/active-net     3324/tcp  # Active Networks<BR>, active-net<br><br>active networks<br>
active-net               3324/udp  # Active Networks<BR>
active-net/active-net     3325/tcp  # Active Networks<BR>, active-net<br><br>active networks<br>
active-net               3325/udp  # Active Networks<BR>
sftu                     3326/tcp  # SFTU<BR>
sftu                     3326/udp  # SFTU<BR>
bbars                    3327/tcp  # BBARS<BR>
bbars                    3327/udp  # BBARS<BR>
egptlm                   3328/tcp  # Eaglepoint License Manager<BR>
egptlm                   3328/udp  # Eaglepoint License Manager<BR>
hp-device-disc           3329/tcp  # HP Device Disc<BR>
hp-device-disc           3329/udp  # HP Device Disc<BR>
mcs-calypsoicf           3330/tcp  # MCS Calypso ICF<BR>
mcs-calypsoicf           3330/udp  # MCS Calypso ICF<BR>
mcs-messaging            3331/tcp  # MCS Messaging<BR>
mcs-messaging            3331/udp  # MCS Messaging<BR>
mcs-mailsvr              3332/tcp  # MCS Mail Server<BR>
mcs-mailsvr              3332/udp  # MCS Mail Server<BR>
dec-notes/eggdrop        3333/tcp  # DEC Notes<BR>, Eggdrop bot<BR>
dec-notes/eggdrop        3333/udp  # DEC Notes<BR>, Eggdrop bot<BR>
directv-web              3334/tcp  # Direct TV Webcasting<BR>
directv-web              3334/udp  # Direct TV Webcasting<BR>
directv-soft             3335/tcp  # Direct TV Software Updates<BR>
directv-soft             3335/udp  # Direct TV Software Updates<BR>
directv-tick             3336/tcp  # Direct TV Tickers<BR>
directv-tick             3336/udp  # Direct TV Tickers<BR>
directv-catlog/directv-catlg     3337/tcp  # Direct TV Data Catelog<BR>, directv-catlg<br><br>direct tv data catalog<br>
directv-catlog/directv-catlg     3337/udp  # Direct TV Data Catelog<BR>, directv-catlg<br><br>direct tv data catalog<br>
anet-b                   3338/tcp  # OMF data b<BR>
anet-b                   3338/udp  # OMF data b<BR>
anet-l                   3339/tcp  # OMF data l<BR>
anet-l                   3339/udp  # OMF data l<BR>
anet-m                   3340/tcp  # OMF data m<BR>
anet-m                   3340/udp  # OMF data m<BR>
anet-h                   3341/tcp  # OMF data h<BR>
anet-h                   3341/udp  # OMF data h<BR>
webtie                   3342/tcp  # WebTIE<BR>
webtie                   3342/udp  # WebTIE<BR>
ms-cluster-net           3343/tcp  # MS Cluster Net<BR>
ms-cluster-net           3343/udp  # MS Cluster Net<BR>
bnt-manager              3344/tcp  # BNT Manager<BR>
bnt-manager              3344/udp  # BNT Manager<BR>
influence                3345/tcp  # Influence<BR>
influence                3345/udp  # Influence<BR>
trnsprntproxy            3346/tcp  # Trnsprnt Proxy<BR>
trnsprntproxy            3346/udp  # Trnsprnt Proxy<BR>
phoenix-rpc              3347/tcp  # Phoenix RPC<BR>
phoenix-rpc              3347/udp  # Phoenix RPC<BR>
pangolin-laser           3348/tcp  # Pangolin Laser<BR>
pangolin-laser           3348/udp  # Pangolin Laser<BR>
chevinservices           3349/tcp  # Chevin Services<BR>
chevinservices           3349/udp  # Chevin Services<BR>
findviatv                3350/tcp  # FINDVIATV<BR>
findviatv                3350/udp  # FINDVIATV<BR>
btrieve                  3351/tcp  # BTRIEVE<BR>
btrieve                  3351/udp  # BTRIEVE<BR>
ssq1/ssql                3352/tcp  # SSQL<BR>, ssql<br><br>ssql<br>
ssq1/ssql                3352/udp  # SSQL<BR>, ssql<br><br>ssql<br>
fatpipe                  3353/tcp  # FATPIPE<BR>
fatpipe                  3353/udp  # FATPIPE<BR>
suitjd                   3354/tcp  # SUITJD<BR>
suitjd                   3354/udp  # SUITJD<BR>
ordinox-dbase            3355/tcp  # Ordinox Dbase<BR>
ordinox-dbase            3355/udp  # Ordinox Dbase<BR>
upnotifyps               3356/tcp  # UPNOTIFYPS<BR>
upnotifyps               3356/udp  # UPNOTIFYPS<BR>
adtech-test              3357/tcp  # Adtech Test IP<BR>
adtech-test              3357/udp  # Adtech Test IP<BR>
mpsysrmsvr               3358/tcp  # Mp Sys Rmsvr<BR>
mpsysrmsvr               3358/udp  # Mp Sys Rmsvr<BR>
wg-netforce              3359/tcp  # WG NetForce<BR>
wg-netforce              3359/udp  # WG NetForce<BR>
kv-server                3360/tcp  # KV Server<BR>
kv-server                3360/udp  # KV Server<BR>
kv-agent                 3361/tcp  # KV Agent<BR>
kv-agent                 3361/udp  # KV Agent<BR>
dj-ilm                   3362/tcp  # DJ ILM<BR>
dj-ilm                   3362/udp  # DJ ILM<BR>
nati-vi-server           3363/tcp  # NATI Vi Server<BR>
nati-vi-server           3363/udp  # NATI Vi Server<BR>
creativeserver           3364/tcp  # Creative Server<BR>
creativeserver           3364/udp  # Creative Server<BR>
contentserver            3365/tcp  # Content Server<BR>
contentserver            3365/udp  # Content Server<BR>
creativepartnr           3366/tcp  # Creative Partner<BR>
creativepartnr           3366/udp  # Creative Partner<BR>
satvid-datalnk/satvid-datalnk     3367/tcp  # Satellite Video Data Link<BR>, satvid-datalnk<br><br>satellite video data link<br>
satvid-datalnk           3367/udp  # Satellite Video Data Link<BR>
satvid-datalnk/satvid-datalnk     3368/tcp  # Satellite Video Data Link<BR>, satvid-datalnk<br><br>satellite video data link<br>
satvid-datalnk           3368/udp  # Satellite Video Data Link<BR>
satvid-datalnk/satvid-datalnk     3369/tcp  # Satellite Video Data Link<BR>, satvid-datalnk<br><br>satellite video data link<br>
satvid-datalnk           3369/udp  # Satellite Video Data Link<BR>
satvid-datalnk/satvid-datalnk     3370/tcp  # Satellite Video Data Link<BR>, satvid-datalnk<br><br>satellite video data link<br>
satvid-datalnk           3370/udp  # Satellite Video Data Link<BR>
satvid-datalnk/satvid-datalnk     3371/tcp  # Satellite Video Data Link<BR>, satvid-datalnk<br><br>satellite video data link<br>
satvid-datalnk           3371/udp  # Satellite Video Data Link<BR>
tip2l/tip2               3372/tcp  # TIP 2<BR>, tip2<br><br>tip 2<br>
tip2l/tip2               3372/udp  # TIP 2<BR>, tip2<br><br>tip 2<br>
lavenir-lm               3373/tcp  # Lavenir License Manager<BR>
lavenir-lm               3373/udp  # Lavenir License Manager<BR>
cluster-disc             3374/tcp  # Cluster Disc<BR>
cluster-disc             3374/udp  # Cluster Disc<BR>
vsnm-agent               3375/tcp  # VSNM Agent<BR>
vsnm-agent               3375/udp  # VSNM Agent<BR>
cdbroker                 3376/tcp  # CD Broker<BR>
cdbroker/cdbroker        3376/udp  # CD Broker<BR>, cdbroker<br><br>cd broker<br>
cogsys-lm                3377/tcp  # Cogsys Network License Manager<BR>
cogsys-lm                3377/udp  # Cogsys Network License Manager<BR>
wsicopy                  3378/tcp  # WSICOPY<BR>
wsicopy                  3378/udp  # WSICOPY<BR>
socorfs                  3379/tcp  # SOCORFS<BR>
socorfs                  3379/udp  # SOCORFS<BR>
sns-channels             3380/tcp  # SNS Channels<BR>
sns-channels             3380/udp  # SNS Channels<BR>
geneous                  3381/tcp  # Geneous<BR>
geneous                  3381/udp  # Geneous<BR>
fujitsu-neat             3382/tcp  # Fujitsu Net Enhanced Antitheft<BR>
fujitsu-neat             3382/udp  # Fujitsu Net Enhanced Antitheft<BR>
esp-lm                   3383/tcp  # Enterprise Software Products LM<BR>
esp-lm                   3383/udp  # Enterprise Software Products LM<BR>
hp-clic                  3384/tcp  # Cluster Management Services<BR>
hp-clic                  3384/udp  # Hardware Management<BR>
qnxnetman                3385/tcp  # qnxnetman<BR>
qnxnetman                3385/udp  # qnxnetman<BR>
gprs-data                3386/tcp  # GPRS Data<BR>
gprs-sig                 3386/udp  # GPRS Signal<BR>
backroomnet              3387/tcp  # Back Room Net<BR>
backroomnet              3387/udp  # Back Room Net<BR>
cbserver                 3388/tcp  # CB Server<BR>
cbserver                 3388/udp  # CB Server<BR>
ms-wbt-server            3389/tcp  # MS Terminal Server RDP Client<BR>
ms-wbt-server/ms-wbt-server     3389/udp  # MS Terminal Server RDP Client<BR>, ms-wbt-server<br><br>ms wbt server<br>
dsc                      3390/tcp  # Distributed Service Coordinator<BR>
dsc                      3390/udp  # Distributed Service Coordinator<BR>
savant                   3391/tcp  # SAVANT<BR>
savant                   3391/udp  # SAVANT<BR>
efi-lm                   3392/tcp  # EFI License Management<BR>
efi-lm                   3392/udp  # EFI License Management<BR>
d2k-tapestry1            3393/tcp  # D2K Tapestry Client to Server<BR>
d2k-tapestry1            3393/udp  # D2K Tapestry Client to Server<BR>
d2k-tapestry2            3394/tcp  # D2K Tapestry Server to Client<BR>
d2k-tapestry2            3394/udp  # D2K Tapestry Server to Client<BR>
dyna-lm                  3395/tcp  # Dyna License Manager (Elam)<BR>
dyna-lm                  3395/udp  # Dyna License Manager (Elam)<BR>
printer_agent            3396/tcp  # Printer Agent<BR>
printer_agent            3396/udp  # Printer Agent<BR>
cloanto-lm               3397/tcp  # Cloanto License Manager<BR>
cloanto-lm               3397/udp  # Cloanto License Manager<BR>
merchantile/mercantile     3398/tcp  # Mercantile<BR>, mercantile<br><br>mercantile<br>
merchantile/mercantile     3398/udp  # Mercantile<BR>, mercantile<br><br>mercantile<br>
csms                     3399/tcp  # CSMS<BR>
csms                     3399/udp  # CSMS<BR>
csms2                    3400/tcp  # CSMC2<BR>
csms2                    3400/udp  # CSMC2<BR>
filecast                 3401/tcp  # FileCast<BR>
filecast                 3401/udp  # FileCast<BR>
bmap                     3421/tcp  # Bull Apprise portmapper<BR>
bmap                     3421/udp  # Bull Apprise portmapper<BR>
mira                     3454/tcp  # Apple Remote Access Protocol<BR>
                         /udp  # 
prsvp                    3455/tcp  # RSVP Port<BR>
prsvp/prsvp              3455/udp  # RSVP Port<BR>, prsvp<br><br>rsvp port, rsvp encapsulated in udp<br>
vat                      3456/tcp  # VAT default data<BR>
vat                      3456/udp  # VAT default data<BR>
vat-control              3457/tcp  # VAT default control<BR>
vat-control              3457/udp  # VAT default control<BR>
d3winosfi                3458/tcp  # D3WinOsfi<BR>
d3winosfi/d3winosfi      3458/udp  # D3WinOsfi<BR>, d3winosfi<br><br>dswinosfi<br>
integral                 3459/tcp  # Integral<BR>
integral                 3459/udp  # Integral<BR>
edm-manager              3460/tcp  # EDM Manager<BR>
edm-manager              3460/udp  # EDM Manager<BR>
edm-stager               3461/tcp  # EDM Stager<BR>
edm-stager               3461/udp  # EDM Stager<BR>
edm-std-notify           3462/tcp  # EDM STD Notify<BR>
edm-std-notify/edm-std-notify     3462/udp  # EDM STD Notify<BR>, edm-std-notify<br><br>edm std notify<br>
edm-adm-notify           3463/tcp  # EDM ADM Notify<BR>
edm-adm-notify           3463/udp  # EDM ADM Notify<BR>
edm-mgr-sync             3464/tcp  # EDM MGR Sync<BR>
edm-mgr-sync             3464/udp  # EDM MGR Sync<BR>
edm-mgr-cntrl            3465/tcp  # EDM MGR Control<BR>
edm-mgr-cntrl            3465/udp  # EDM MGR Control<BR>
workflow                 3466/tcp  # WORKFLOW<BR>
workflow                 3466/udp  # WORKFLOW<BR>
rcst                     3467/tcp  # RCST<BR>
rcst                     3467/udp  # RCST<BR>
ttcmremotectrl           3468/tcp  # TTCM Remote Control<BR>
ttcmremotectrl           3468/udp  # TTCM Remote Control<BR>
pluribus                 3469/tcp  # Pluribus<BR>
pluribus                 3469/udp  # Pluribus<BR>
jt400                    3470/tcp  # jt400<BR>
jt400                    3470/udp  # jt400<BR>
jt400-ssl                3471/tcp  # jt400 SSL<BR>
jt400-ssl                3471/udp  # jt400 SSL<BR>
watcomdebug              3472/tcp  # Watcom Debug<BR>
watcomdebug              3472/udp  # Watcom Debug<BR>
harlequinorb             3473/tcp  # harlequinorb<BR>
harlequinorb             3473/udp  # harlequinorb<BR>
ms-la                    3535/tcp  # MS-LA<BR>
ms-la                    3535/udp  # MS-LA<BR>
vhd                      3802/tcp  # VHD<BR>
vhd                      3802/udp  # VHD<BR>
v-one-spp                3845/tcp  # V-ONE Single Port Proxy<BR>
v-one-spp                3845/udp  # V-ONE Single Port Proxy<BR>
udt_os                   3900/tcp  # Unidata UDT OS<BR>
udt_os                   3900/udp  # Unidata UDT OS<BR>
mapper-nodemgr           3984/tcp  # MAPPER network node manager<BR>
mapper-nodemgr           3984/udp  # MAPPER network node manager<BR>
mapper-mapethd           3985/tcp  # MAPPER TCP/IP server<BR>
mapper-mapethd           3985/udp  # MAPPER TCP/IP server<BR>
mapper-ws_ethd           3986/tcp  # MAPPER workstation server<BR>
mapper-ws_ethd           3986/udp  # MAPPER workstation server<BR>
centerline               3987/tcp  # Centerline<BR>
centerline               3987/udp  # Centerline<BR>
terabase/icq-tcp         4000/tcp  # Terabase<BR>, ICQ Control Port<BR><br> Used to negotiate random-high udp ports for ICQ data tx. <BR> 
terabase/icq-udp         4000/udp  # Terabase<BR>, ICQ Data Port<BR>
newoak                   4001/tcp  # NewOak<BR>
newoak                   4001/udp  # NewOak<BR>
pxc-spvr-ft              4002/tcp  # pxc-spvr-ft<BR>
pxc-spvr-ft              4002/udp  # pxc-spvr-ft<BR>
pxc-splr-ft              4003/tcp  # pxc-splr-ft<BR>
pxc-splr-ft              4003/udp  # pxc-splr-ft<BR>
pxc-roid                 4004/tcp  # pxc-roid<BR>
pxc-roid                 4004/udp  # pxc-roid<BR>
pxc-pin                  4005/tcp  # pxc-pin<BR>
pxc-pin                  4005/udp  # pxc-pin<BR>
pxc-spvr                 4006/tcp  # pxc-spvr<BR>
pxc-spvr                 4006/udp  # pxc-spvr<BR>
pxc-splr                 4007/tcp  # pxc-splr<BR>
pxc-splr                 4007/udp  # pxc-splr<BR>
netcheque                4008/tcp  # NetCheque accounting<BR>
netcheque                4008/udp  # NetCheque accounting<BR>
chimera-hwm              4009/tcp  # Chimera HWM<BR>
chimera-hwm              4009/udp  # Chimera HWM<BR>
samsung-unidex           4010/tcp  # Samsung Unidex<BR>
samsung-unidex           4010/udp  # Samsung Unidex<BR>
altserviceboot           4011/tcp  # Alternate Service Boot<BR>
altserviceboot           4011/udp  # Alternate Service Boot<BR>
pda-gate                 4012/tcp  # PDA Gate<BR>
pda-gate                 4012/udp  # PDA Gate<BR>
acl-manager              4013/tcp  # ACL Manager<BR>
acl-manager              4013/udp  # ACL Manager<BR>
taiclock                 4014/tcp  # TAICLOCK<BR>
taiclock                 4014/udp  # TAICLOCK<BR>
talarian-mcast1          4015/tcp  # Talarian Mcast<BR>
talarian-mcast1          4015/udp  # Talarian Mcast<BR>
talarian-mcast2          4016/tcp  # Talarian Mcast<BR>
talarian-mcast2          4016/udp  # Talarian Mcast<BR>
talarian-mcast3          4017/tcp  # Talarian Mcast<BR>
talarian-mcast3          4017/udp  # Talarian Mcast<BR>
talarian-mcast4          4018/tcp  # Talarian Mcast<BR>
talarian-mcast4          4018/udp  # Talarian Mcast<BR>
talarian-mcast5          4019/tcp  # Talarian Mcast<BR>
talarian-mcast5          4019/udp  # Talarian Mcast<BR>
ichat                    4020/tcp  # IChat Chat Room<BR>
ichat                    4020/udp  # IChat Chat Room<BR>
lockd                    4045/tcp  # NFS lock daemon (alt port)<BR><br> Supports record locking on NFS files. On some OS's (eg: Solaris), lockd tracks NFS requests to tcp 2049. Attackers know this and will probe NFS via tcp 4045 instead, hoping probe escapes detection. <BR> 
lockd/lockd              4045/udp  # NFS lock daemon (alt port)<BR><br> Supports record locking on NFS files. On some OS's (eg: Solaris), lockd tracks NFS requests to tcp 2049. Attackers know this and will probe NFS via tcp 4045 instead, hoping probe escapes detection. <BR> , lockd<br><br>nfs lock daemon/manager<br>
bre                      4096/tcp  # Bridge Relay Element<BR>
bre                      4096/udp  # Bridge Relay Element<BR>
patrolview               4097/tcp  # Patrol View<BR>
patrolview               4097/udp  # Patrol View<BR>
drmsfsd                  4098/tcp  # drmsfsd<BR>
drmsfsd                  4098/udp  # drmsfsd<BR>
dpcp                     4099/tcp  # DPCD<BR>
dpcp                     4099/udp  # DPCD<BR>
nuts_dem                 4132/tcp  # NUTS Daemon<BR>
nuts_dem                 4132/udp  # NUTS Daemon<BR>
nuts_bootp               4133/tcp  # NUTS Bootp Server<BR>
nuts_bootp               4133/udp  # NUTS Bootp Server<BR>
nifty-hmi                4134/tcp  # NIFTY-Serve HMI protocol<BR>
nifty-hmi                4134/udp  # NIFTY-Serve HMI protocol<BR>
oirtgsvc                 4141/tcp  # Workflow Server<BR>
oirtgsvc                 4141/udp  # Workflow Server<BR>
oidocsvc                 4142/tcp  # Document Server<BR>
oidocsvc                 4142/udp  # Document Server<BR>
oidsr                    4143/tcp  # Document Replication<BR>
oidsr                    4143/udp  # Document Replication<BR>
CIM/wincim               4144/tcp  # Compuserve server port<BR>, wincim<br><br>pc windows compuserve.com protocol<br>
CIM                      4144/udp  # Compuserve server port<BR>
jini-discovery           4160/tcp  # Jini Discovery<BR>
jini-discovery           4160/udp  # Jini Discovery<BR>
eims=admin/eims-admin     4199/tcp  # EIMS Admin<BR>, eims-admin<br><br>eims admin<br>
eims=admin/eims-admin     4199/udp  # EIMS Admin<BR>, eims-admin<br><br>eims admin<br>
vrml-multi-use/vrml-multi-use     4200/tcp  # VRML Multi User Systems<BR>, vrml-multi-use<br><br>vrml multi user systems<br>
vrml-multi-use           4200/udp  # VRML Multi User Systems<BR>
corelccam                4300/tcp  # Corel Ccam<BR>
corelccam                4300/udp  # Corel Ccam<BR>
rwhois                   4321/tcp  # Remote Who Is<BR>
rwhois                   4321/udp  # Remote Who Is<BR>
unicall                  4343/tcp  # UNICALL<BR>
unicall                  4343/udp  # UNICALL<BR>
vinainstall              4344/tcp  # VinaInstall<BR>
vinainstall              4344/udp  # VinaInstall<BR>
m4-network-as            4345/tcp  # Macro 4 Network AS<BR>
m4-network-as            4345/udp  # Macro 4 Network AS<BR>
elanlm                   4346/tcp  # ELAN LM<BR>
elanlm                   4346/udp  # ELAN LM<BR>
lansurveyor              4347/tcp  # LAN Surveyor<BR>
lansurveyor              4347/udp  # LAN Surveyor<BR>
itose                    4348/tcp  # ITOSE<BR>
itose                    4348/udp  # ITOSE<BR>
fsportmap                4349/tcp  # File System Port Map<BR>
fsportmap                4349/udp  # File System Port Map<BR>
net-device               4350/tcp  # Net Device<BR>
net-device               4350/udp  # Net Device<BR>
plcy-net-svcs            4351/tcp  # PLCY Net Services<BR>
plcy-net-svcs            4351/udp  # PLCY Net Services<BR>
f5-iquery                4353/tcp  # F5iQuery<BR>
f5-iquery                4353/udp  # F5iQuery<BR>
saris                    4442/tcp  # Saris<BR>
saris                    4442/udp  # Saris<BR>
pharos                   4443/tcp  # Pharos<BR>
pharos                   4443/udp  # Pharos<BR>
krb524/nv-video/eggdrop     4444/tcp  # KRB524<BR>, NV Video default<BR>, Common for eggdrop bot<BR>
krb524/nv-video/eggdrop/krb524     4444/udp  # KRB524<BR>, NV Video default<BR>, Common for eggdrop bot<BR>, krb524<br><br>nv video default, krb524<br>
upnotifyp                4445/tcp  # UPNOTIFYP<BR>
upnotifyp                4445/udp  # UPNOTIFYP<BR>
n1-fwp                   4446/tcp  # N1-FWP<BR>
n1-fwp                   4446/udp  # N1-FWP<BR>
n1-rmgmt                 4447/tcp  # N1-RMGMT<BR>
n1-rmgmt                 4447/udp  # N1-RMGMT<BR>
asc-slmd                 4448/tcp  # ASC Licence Manager<BR>
asc-slmd                 4448/udp  # ASC Licence Manager<BR>
arcryptoip/privatewire     4449/tcp  # ARCrypto IP<BR>, PrivateWire<BR>
arcryptoip/privatewire     4449/udp  # ARCrypto IP<BR>, PrivateWire<BR>
camp                     4450/tcp  # Camp<BR>
camp                     4450/udp  # Camp<BR>
ctisystemmsg             4451/tcp  # CTI System Msg<BR>
ctisystemmsg             4451/udp  # CTI System Msg<BR>
ctiprogramload           4452/tcp  # CTI Program Load<BR>
ctiprogramload           4452/udp  # CTI Program Load<BR>
nssalertmgr              4453/tcp  # NSS Alert Manager<BR>
nssalertmgr              4453/udp  # NSS Alert Manager<BR>
nssagentmgr              4454/tcp  # NSS Agent Manager<BR>
nssagentmgr              4454/udp  # NSS Agent Manager<BR>
prchat-user              4455/tcp  # PR Chat User<BR>
prchat-user              4455/udp  # PR Chat User<BR>
prchat-server            4456/tcp  # PR Chat Server<BR>
prchat-server            4456/udp  # PR Chat Server<BR>
prRegister               4457/tcp  # PR Register<BR>
prRegister               4457/udp  # PR Register<BR>
sae-urn                  4500/tcp  # sae-urn<BR>
sae-urn/NAT-T            4500/udp  # sae-urn<BR>, NAT-T (NAT transparency) in ISAKMP negotiations for IPSec.
urn-x-cdchoice           4501/tcp  # urn-x-cdchoice<BR>
urn-x-cdchoice           4501/udp  # urn-x-cdchoice<BR>
worldscores              4545/tcp  # WorldScores<BR>
worldscores              4545/udp  # WorldScores<BR>
sf-lm                    4546/tcp  # SF License Manager (Sentinel)<BR>
sf-lm                    4546/udp  # SF License Manager (Sentinel)<BR>
lanner-lm                4547/tcp  # Lanner License Manager<BR>
lanner-lm                4547/udp  # Lanner License Manager<BR>
tram                     4567/tcp  # TRAM<BR>
tram                     4567/udp  # TRAM<BR>
bmc-reporting            4568/tcp  # BMC Reporting<BR>
bmc-reporting            4568/udp  # BMC Reporting<BR>
piranha1                 4600/tcp  # Piranha-1<BR>
piranha1                 4600/udp  # Piranha-1<BR>
piranha2                 4601/tcp  # Piranha-2<BR>
piranha2                 4601/udp  # Piranha-2<BR>
rfa                      4672/tcp  # remote file access server
EMule, rfa               4672/udp  # P2P, remote file access server
                         /tcp  # 
pgpfone                  4747/udp  # PGP Secure Phone Data Stream<BR>
iims                     4800/tcp  # Icona Instant Messenging System<BR>
iims                     4800/udp  # Icona Instant Messenging System<BR>
iwec                     4801/tcp  # Icona Web Embedded Chat<BR>
iwec                     4801/udp  # Icona Web Embedded Chat<BR>
ilss                     4802/tcp  # Icona License System Server<BR>
ilss                     4802/udp  # Icona License System Server<BR>
htcp                     4827/tcp  # HTCP<BR>
htcp                     4827/udp  # HTCP<BR>
phrelay                  4868/tcp  # Photon Relay<BR>
phrelay                  4868/udp  # Photon Relay<BR>
phrelaydbg               4869/tcp  # Photon Relay Debug<BR>
phrelaydbg               4869/udp  # Photon Relay Debug<BR>
abbs                     4885/tcp  # ABBS<BR>
abbs                     4885/udp  # ABBS<BR>
att-intercom             4983/tcp  # AT&amp;T Intercom<BR>
att-intercom             4983/udp  # AT&amp;T Intercom<BR>
sockets-de-troje/commplex-main/Sybase/nortel-voip/YahooMessenger     5000/tcp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5001, 30303, 50505. <BR> , Complex Main<BR>, , Nortel Networks i2050 Software Phone, Yahoo Messenger Voice Chat
sockets-de-troje/commplex-main/commplex-main/nortel-voip     5000/udp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5001, 30303, 50505. <BR> , Complex Main<BR>, commplex-main<br><br><br>, Nortel Networks i2050 Software Phone
commplex-link/sockets-de-troje/YahooMessenger     5001/tcp  # Complex Link<BR>, Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 30303, 50505. <BR> , Yahoo Messenger Voice Chat
commplex-link/sockets-de-troje     5001/udp  # Complex Link<BR>, Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 30303, 50505. <BR> 
rfe                      5002/tcp  # radio free ethernet<BR>
rfe/rfe                  5002/udp  # radio free ethernet<BR>, rfe<br><br>radio free ethernet, actually uses udp only<br>
claris-fmpro/fmpro-internal     5003/tcp  # Claris FileMaker Pro<BR>, FileMaker - Proprietary Transport<BR>
claris-fmpro/fmpro-internal/fmpro-internal     5003/udp  # Claris FileMaker Pro<BR>, FileMaker - Proprietary Transport<BR>, fmpro-internal<br><br>filemaker, inc. - proprietary name binding<br>
avt-profile-1            5004/tcp  # avt-profile-1<BR>
avt-profile-1            5004/udp  # avt-profile-1<BR>
avt-profile-2            5005/tcp  # avt-profile-2<BR>
avt-profile-2            5005/udp  # avt-profile-2<BR>
wsm-server               5006/tcp  # WSM Server<BR>
wsm-server               5006/udp  # WSM Server<BR>
wsm-server-ssl           5007/tcp  # WSM Server SSL<BR>
wsm-server-ssl           5007/udp  # WSM Server SSL<BR>
telelpathstart           5010/tcp  # TelepathStart<BR>
telelpathstart           5010/udp  # TelepathStart<BR>
telelpathattack          5011/tcp  # TelepathAttack<BR>
telelpathattack          5011/udp  # TelepathAttack<BR>
zenginkyo-1              5020/tcp  # zenginkyo-1<BR>
zenginkyo-1              5020/udp  # zenginkyo-1<BR>
zenginkyo-2              5021/tcp  # zenginkyo-2<BR>
zenginkyo-2              5021/udp  # zenginkyo-2<BR>
asnaacceler8db           5042/tcp  # asnaacceler8db<BR>
asnaacceler8db           5042/udp  # asnaacceler8db<BR>
mmcc                     5050/tcp  # multimedia conference control tool<BR>
mmcc                     5050/udp  # multimedia conference control tool<BR>
ita-manager/ita-agent     5051/tcp  # ITA Manager<BR><br> Open on Axent ITA Manager, to receive comms from agents. <BR> , ita-agent<br><br>ita agent<br>
ita-agent                5051/udp  # ita-agent<br><br>ita agent<br>
ita-agent/ita-manager     5052/tcp  # ITA Agent<BR><br> Open on Axent ITA agents, to receive comms from manager. <BR> , ita-manager<br><br>ita manager<br>
ita-manager              5052/udp  # ita-manager<br><br>ita manager<br>
unot                     5055/tcp  # UNOT<BR>
unot                     5055/udp  # UNOT<BR>
sip/hp-chorus            5060/tcp  # SIP<BR>, HP Motive Chorus (HTTP)
sip                      5060/udp  # SIP<BR>
I-net-2000-npr           5069/tcp  # I/Net 2000-NPR<BR>
I-net-2000-npr           5069/udp  # I/Net 2000-NPR<BR>
powerschool              5071/tcp  # PowerSchool<BR>
powerschool              5071/udp  # PowerSchool<BR>
rmonitor_secure          5145/tcp  # rmonitor secure<BR>
rmonitor_secure          5145/udp  # rmonitor secure<BR>
atmp                     5150/tcp  # Ascend Tunnel Management Protocol<BR>
atmp                     5150/udp  # Ascend Tunnel Management Protocol<BR>
esri_sde                 5151/tcp  # ESRI SDE Instance<BR>
esri_sde                 5151/udp  # ESRI SDE Remote Start<BR>
sde-discovery            5152/tcp  # ESRI SDE Instance Discovery<BR>
sde-discovery            5152/udp  # ESRI SDE Instance Discovery<BR>
ife_icorp                5165/tcp  # ife_1corp<BR>
ife_icorp                5165/udp  # ife_1corp<BR>
aol                      5190/tcp  # America-Online Server Port<BR><br> Primary AOL Internet-connect port; also used in Instant Messaging. Alternate ports: 5191, 5192, 5193. <BR> 
aol                      5190/udp  # America-Online Server Port<BR><br> Primary AOL Internet-connect port; also used in Instant Messaging. Alternate ports: 5191, 5192, 5193. <BR> 
aol-1                    5191/tcp  # America-Online1 Server Port<BR>
aol-1                    5191/udp  # America-Online1 Server Port<BR>
aol-2                    5192/tcp  # America-Online2 Server Port<BR>
aol-2                    5192/udp  # America-Online2 Server Port<BR>
aol-3                    5193/tcp  # America-Online3 Server Port<BR>
aol-3                    5193/udp  # America-Online3 Server Port<BR>
targus-aib1              5200/tcp  # Targus AIB 1<BR>
targus-aib1              5200/udp  # Targus AIB 1<BR>
targus-aib2              5201/tcp  # Targus AIB 2<BR>
targus-aib2              5201/udp  # Targus AIB 2<BR>
targus-tnts1             5202/tcp  # Targus TNTS 1<BR>
targus-tnts1             5202/udp  # Targus TNTS 1<BR>
targus-tnts2             5203/tcp  # Targus TNTS 2<BR>
targus-tnts2             5203/udp  # Targus TNTS 2<BR>
padl2sim                 5236/tcp  # padl2sim<BR>
padl2sim                 5236/udp  # padl2sim<BR>
pk                       5272/tcp  # 
pk                       5272/udp  # 
hacl-hb                  5300/tcp  # HA cluster heartbeat<BR>
hacl-hb                  5300/udp  # HA cluster heartbeat<BR>
hacl-gs                  5301/tcp  # HA cluster general services<BR>
hacl-gs                  5301/udp  # HA cluster general services<BR>
hacl-cfg                 5302/tcp  # HA cluster configuration<BR>
hacl-cfg                 5302/udp  # HA cluster configuration<BR>
hacl-probe               5303/tcp  # HA cluster probing<BR>
hacl-probe               5303/udp  # HA cluster probing<BR>
hacl-local               5304/tcp  # HA Cluster Commands<BR>
hacl-local/hacl-local     5304/udp  # HA Cluster Commands<BR>, hacl-local<br><br><br>
hacl-test                5305/tcp  # HA Cluster Test<BR>
hacl-test/hacl-test      5305/udp  # HA Cluster Test<BR>, hacl-test<br><br><br>
sun-mc-grp               5306/tcp  # Sun MC Group<BR>
sun-mc-grp               5306/udp  # Sun MC Group<BR>
sco-aip                  5307/tcp  # SCO AIP<BR>
sco-aip                  5307/udp  # SCO AIP<BR>
cfengine                 5308/tcp  # CFengine<BR>
cfengine                 5308/udp  # CFengine<BR>
jprinter                 5309/tcp  # J Printer<BR>
jprinter                 5309/udp  # J Printer<BR>
outlaws                  5310/tcp  # Outlaws<BR>
outlaws                  5310/udp  # Outlaws<BR>
tmlogin                  5311/tcp  # TM Login<BR>
tmlogin                  5311/udp  # TM Login<BR>
excerpt                  5400/tcp  # Excerpt Search<BR>
excerpt                  5400/udp  # Excerpt Search<BR>
excerpts                 5401/tcp  # Excerpt Search Secure<BR>
excerpts                 5401/udp  # Excerpt Search Secure<BR>
mftp                     5402/tcp  # MFTP<BR>
mftp                     5402/udp  # MFTP<BR>
hpoms-ci-lstn            5403/tcp  # HPOMS-CI-LSTN<BR>
hpoms-ci-lstn            5403/udp  # HPOMS-CI-LSTN<BR>
hpoms-dps-lstn           5404/tcp  # HPOMS-DPS-LSTN<BR>
hpoms-dps-lstn           5404/udp  # HPOMS-DPS-LSTN<BR>
netsupport               5405/tcp  # NetSupport<BR>
netsupport               5405/udp  # NetSupport<BR>
systemics-sox            5406/tcp  # Systemics Sox<BR>
systemics-sox            5406/udp  # Systemics Sox<BR>
foresyte-clear           5407/tcp  # Foresyte-Clear<BR>
foresyte-clear           5407/udp  # Foresyte-Clear<BR>
foresyte-sec             5408/tcp  # Foresyte-Sec<BR>
foresyte-sec             5408/udp  # Foresyte-Sec<BR>
salient-dtasrv           5409/tcp  # Salient Data Server<BR>
salient-dtasrv           5409/udp  # Salient Data Server<BR>
salient-usrmgr           5410/tcp  # Salient User Manager<BR>
salient-usrmgr           5410/udp  # Salient User Manager<BR>
actnet                   5411/tcp  # ActNet<BR>
actnet                   5411/udp  # ActNet<BR>
continuus                5412/tcp  # Continuus<BR>
continuus                5412/udp  # Continuus<BR>
wwiotalk                 5413/tcp  # WWIOTALK<BR>
wwiotalk                 5413/udp  # WWIOTALK<BR>
statusd                  5414/tcp  # StatusD<BR>
statusd                  5414/udp  # StatusD<BR>
ns-server                5415/tcp  # NS Server<BR>
ns-server                5415/udp  # NS Server<BR>
sns-gateway              5416/tcp  # SNS Gateway<BR>
sns-gateway              5416/udp  # SNS Gateway<BR>
sns-agent                5417/tcp  # SNS Agent<BR>
sns-agent                5417/udp  # SNS Agent<BR>
mcntp                    5418/tcp  # MCNTP<BR>
mcntp                    5418/udp  # MCNTP<BR>
dj-ice                   5419/tcp  # DJ-ICE<BR>
dj-ice                   5419/udp  # DJ-ICE<BR>
cylink-c                 5420/tcp  # Cylink-C<BR>
cylink-c                 5420/udp  # Cylink-C<BR>
netsupport2              5421/tcp  # Net Support 2<BR>
netsupport2              5421/udp  # Net Support 2<BR>
salient-mux              5422/tcp  # Salient Multiplexor<BR>
salient-mux              5422/udp  # Salient Multiplexor<BR>
virtualuser              5423/tcp  # VirtualUser<BR>
virtualuser              5423/udp  # VirtualUser<BR>
bmc-perf-ad              5424/tcp  # BMC-PERF-SD<BR>
bmc-perf-ad              5424/udp  # BMC-PERF-SD<BR>
bmc-perf-agnt            5425/tcp  # BMC-PERF-Agent<BR>
bmc-perf-agnt            5425/udp  # BMC-PERF-Agent<BR>
devbasic                 5426/tcp  # DevBasic<BR>
devbasic                 5426/udp  # DevBasic<BR>
sco-peer-tta             5427/tcp  # SCO Peer-TTA<BR>
sco-peer-tta             5427/udp  # SCO Peer-TTA<BR>
telaconsole              5428/tcp  # TelaConsole<BR>
telaconsole              5428/udp  # TelaConsole<BR>
base                     5429/tcp  # Billing and Accounting System Exchange<BR>
base                     5429/udp  # Billing and Accounting System Exchange<BR>
radec-corp               5430/tcp  # RADEC Corp<BR>
radec-corp               5430/udp  # RADEC Corp<BR>
park-agent               5431/tcp  # PARK Agent<BR>
park-agent/park-agnet     5431/udp  # PARK Agent<BR>, park-agnet<br><br>park agent<br>
apc-tcp-udp-4            5454/tcp  # apc-tcp-udp-4<BR>
apc-tcp-udp-4            5454/udp  # apc-tcp-udp-4<BR>
apc-tcp-udp-5            5455/tcp  # apc-tcp-udp-5<BR>
apc-tcp-udp-5            5455/udp  # apc-tcp-udp-5<BR>
apc-tcp-udp-6            5456/tcp  # apc-tcp-udp-6<BR>
apc-tcp-udp-6            5456/udp  # apc-tcp-udp-6<BR>
silkmeter                5461/tcp  # SilkMeter<BR>
silkmeter                5461/udp  # SilkMeter<BR>
fcp-addr-srvr1           5500/tcp  # fcp-addr-srvr1<BR>
securid/fcp-addr-srvr1/fcp-addr-srvr1     5500/udp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> , fcp-addr-srvr1<BR>, fcp-addr-srvr1<br><br>fcp-addr-srvr1, securid<br>
fcp-addr-srvr2           5501/tcp  # fcp-addr-srvr2<BR>
fcp-addr-srvr2           5501/udp  # fcp-addr-srvr2<BR>
fcp-addr-inst1/fcp-srvr-inst1     5502/tcp  # fcp-addr-inst2<BR>, fcp-srvr-inst1<br><br>fcp-srvr-inst1<br>
fcp-addr-inst1/fcp-srvr-inst1     5502/udp  # fcp-addr-inst2<BR>, fcp-srvr-inst1<br><br>fcp-srvr-inst1<br>
fcp-addr-inst2/fcp-srvr-inst2     5503/tcp  # fcp-addr-inst2<BR>, fcp-srvr-inst2<br><br>fcp-srvr-inst2<br>
fcp-addr-inst2/fcp-srvr-inst2     5503/udp  # fcp-addr-inst2<BR>, fcp-srvr-inst2<br><br>fcp-srvr-inst2<br>
fcp-cics-gw1             5504/tcp  # fcp-cics-gw1<BR>
fcp-cics-gw1             5504/udp  # fcp-cics-gw1<BR>
securidprop/secureidprop     5510/tcp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> , secureidprop<br><br>ace/server services<br>
                         /udp  # 
sdlog                    5520/tcp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> 
                         /udp  # 
sdserv                   5530/tcp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> 
                         /udp  # 
sdreport                 5540/tcp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> 
sdxauth/sdxauthd         5540/udp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> , sdxauthd<br><br>ace/server services<br>
sdadmin/sdadmind         5550/tcp  # SecurID Services<BR><br> SecurID Services use: <BR> - tcp 5510, 5520, 5530, 5540, 5550 <BR> - udp 5500, 5540 <BR> , sdadmind<br><br>ace/server services<br>
                         /udp  # 
sgi-esphttp              5554/tcp  # SGI ESP HTTP<BR>
sgi-esphttp              5554/udp  # SGI ESP HTTP<BR>
omni/rmt/personal-agent/eggdrop     5555/tcp  # OmniBack-II<BR>, Rmtd<BR>, Personal Agent<BR>, Common for eggdrop bot<BR>
personal-agent/eggdrop     5555/udp  # Personal Agent<BR>, Common for eggdrop bot<BR>
mtb                      5556/tcp  # Mtbd (mtb backup)<BR>
                         /udp  # 
esinstall                5599/tcp  # Enterprise Security Remote Install<BR>
esinstall                5599/udp  # Enterprise Security Remote Install<BR>
esm-agent/esmmanager     5600/tcp  # Enterprise Security Agent - Unix     Open on Axent ESM Unix agents, to receive comms from its manager.  Data is encrypted during transfer., esmmanager<br><br>enterprise security manager<br>
esmmanager               5600/udp  # esmmanager<br><br>enterprise security manager<br>
esm-agent/esm-manager/esmagent     5601/tcp  # Enterprise Security Agent - NT<BR><br> Open on Axent ESM NT agents, to receive comms from its manager. <BR> , Enterprise Security Manager<BR><br> Open on Axent ESM manager, to receive comms from its agents. <BR> , esmagent<br><br>enterprise security agent<br>
esmagent                 5601/udp  # esmagent<br><br>enterprise security agent<br>
a1-msc                   5602/tcp  # A1-MSC<BR>
a1-msc                   5602/udp  # A1-MSC<BR>
a1-bs                    5603/tcp  # A1-BS<BR>
a1-bs                    5603/udp  # A1-BS<BR>
a3-sdunode               5604/tcp  # A3-SDUNode<BR>
a3-sdunode               5604/udp  # A3-SDUNode<BR>
a4-sdunode               5605/tcp  # A4-SDUNode<BR>
a4-sdunode               5605/udp  # A4-SDUNode<BR>
pcanywheredata/pcanywheredata     5631/tcp  # pcAnywhere Data<BR><br> Default tcp port for v7.52 and above. v2.0 thru v7.51, plus CE version, use tcp 65301 &amp; udp 22. <BR> , pcanywheredata<br><br>pcanywheredata<br>
pcanywheredata           5631/udp  # pcanywheredata<br><br>pcanywheredata<br>
pcanywherestat           5632/tcp  # pcanywherestat<br><br>pcanywherestat<br>
pcanywherestat/pcanywherestat     5632/udp  # pcAnywhere Status<BR><br> Default udp port for v7.52 and above. v2.0 thru v7.51, plus CE version, use tcp 65301 &amp; udp 22. <BR> , pcanywherestat<br><br>pcanywherestat<br>
rrac                     5678/tcp  # Remote Replication Agent Connection<BR>
rrac                     5678/udp  # Remote Replication Agent Connection<BR>
dccm                     5679/tcp  # Direct Cable Connect Manager<BR>
dccm                     5679/udp  # Direct Cable Connect Manager<BR>
proshareaudio            5713/tcp  # proshare conf audio<BR>
proshareaudio            5713/udp  # proshare conf audio<BR>
prosharevideo            5714/tcp  # proshare conf video<BR>
prosharevideo            5714/udp  # proshare conf video<BR>
prosharedata             5715/tcp  # proshare conf data<BR>
prosharedata             5715/udp  # proshare conf data<BR>
prosharerequest          5716/tcp  # proshare conf request<BR>
prosharerequest          5716/udp  # proshare conf request<BR>
prosharenotify           5717/tcp  # proshare conf notify<BR>
prosharenotify           5717/udp  # proshare conf notify<BR>
openmail                 5729/tcp  # Openmail User Agent Layer<BR>
openmail                 5729/udp  # Openmail User Agent Layer<BR>
ida-discover1            5741/tcp  # IDA Discover Port1<BR>
ida-discover1            5741/udp  # IDA Discover Port1<BR>
ida-discover2            5742/tcp  # IDA Discover Port 2<BR>
ida-discover2            5742/udp  # IDA Discover Port 2<BR>
fcopy-server             5745/tcp  # fcopy-server<BR>
fcopy-server             5745/udp  # fcopy-server<BR>
fcopys-server            5746/tcp  # fcopys-server<BR>
fcopys-server            5746/udp  # fcopys-server<BR>
openmailg                5755/tcp  # OpenMail Desk Gateway server<BR>
openmailg                5755/udp  # OpenMail Desk Gateway server<BR>
x500ms                   5757/tcp  # OpenMail X.500 Directory Server<BR>
x500ms                   5757/udp  # OpenMail X.500 Directory Server<BR>
openmailns               5766/tcp  # OpenMail NewMail Server<BR>
openmailns               5766/udp  # OpenMail NewMail Server<BR>
s-openmail               5767/tcp  # OpenMail Suer Agent Layer (Secure)<BR>
s-openmail               5767/udp  # OpenMail Suer Agent Layer (Secure)<BR>
openmailpxy              5768/tcp  # OpenMail CMTS Server<BR>
openmailpxy              5768/udp  # OpenMail CMTS Server<BR>
netagent                 5771/tcp  # NetAgent<BR>
netagent                 5771/udp  # NetAgent<BR>
mppolicy-v5              5968/tcp  # MM Policy v5<BR>
mppolicy-v5              5968/udp  # MM Policy v5<BR>
mppolicy-mgr             5969/tcp  # MP Policy Manager<BR>
mppolicy-mgr             5969/udp  # MP Policy Manager<BR>
x11                      6000/tcp  # X-Window System<BR><br> X11 ports to support remote x-windows sessions. Sessions are vulnerable to spoofing, session hijacking, capture of user screen data, keystroke monitoring, insertion of hostile keystrokes &amp; commands, data diddling, and DOS. <BR> <br> Review x-windows security techniques; do not run default x-windows server config's in production environment! <BR> 
x11/x11                  6000/udp  # X-Window System<BR><br> X11 ports to support remote x-windows sessions. Sessions are vulnerable to spoofing, session hijacking, capture of user screen data, keystroke monitoring, insertion of hostile keystrokes &amp; commands, data diddling, and DOS. <BR> <br> Review x-windows security techniques; do not run default x-windows server config's in production environment! <BR> , x11<br><br>x window system<br>
softcm                   6110/tcp  # HP SoftBench CM<BR>
softcm                   6110/udp  # HP SoftBench CM<BR>
spc                      6111/tcp  # HP SoftBench Sub-Process Control<BR>
spc                      6111/udp  # HP SoftBench Sub-Process Control<BR>
dtspcd                   6112/tcp  # dtspcd<BR>
dtspcd/dtspcd            6112/udp  # dtspcd<BR>, dtspcd<br><br>dtspcd<br>
backup-express           6123/tcp  # Backup Express<BR>
backup-express           6123/udp  # Backup Express<BR>
meta-corp                6141/tcp  # Meta Corporation License Manager<BR>
meta-corp                6141/udp  # Meta Corporation License Manager<BR>
aspentec-lm              6142/tcp  # Aspen Technology License Manager<BR>
aspentec-lm              6142/udp  # Aspen Technology License Manager<BR>
watershed-lm             6143/tcp  # Watershed License Manager<BR>
watershed-lm             6143/udp  # Watershed License Manager<BR>
statsci1-lm              6144/tcp  # StatSci License Manager - 1<BR>
statsci1-lm              6144/udp  # StatSci License Manager - 1<BR>
statsci2-lm              6145/tcp  # StatSci License Manager - 2<BR>
statsci2-lm              6145/udp  # StatSci License Manager - 2<BR>
lonewolf-lm              6146/tcp  # Lone Wolf Systems License Manager<BR>
lonewolf-lm              6146/udp  # Lone Wolf Systems License Manager<BR>
montage-lm               6147/tcp  # Montage License Manager<BR>
montage-lm               6147/udp  # Montage License Manager<BR>
ricardo-lm               6148/tcp  # Ricardo North America License Manager<BR>
ricardo-lm               6148/udp  # Ricardo North America License Manager<BR>
tal-pod                  6149/tcp  # tal-pod<BR>
tal-pod                  6149/udp  # tal-pod<BR>
crip                     6253/tcp  # CRIP<BR>
crip                     6253/udp  # CRIP<BR>
                         /tcp  # 
roadrunner               6284/udp  # RoadRunner Cable Modem "Keep Alive"<BR><br> Operates in conjunction with tcp 7283 (Roadrunner Logon). <BR> 
clariion-evr01           6389/tcp  # clariion-evr01<BR>
clariion-evr01           6389/udp  # clariion-evr01<BR>
info-aps/info-aps        6400/tcp  # Info - APS<BR>, info-aps<br><br><br>
info-aps                 6400/udp  # Info - APS<BR>
info-was/info-was        6401/tcp  # Info - WAS<BR>, info-was<br><br><br>
info-was                 6401/udp  # Info - WAS<BR>
info-eventsvr/info-eventsvr     6402/tcp  # Info - Event Server<BR>, info-eventsvr<br><br><br>
info-eventsvr            6402/udp  # Info - Event Server<BR>
info-filesvr/info-filesvr     6404/tcp  # Info - File Server<BR>, info-filesvr<br><br><br>
info-filesvr             6404/udp  # Info - File Server<BR>
info-pagesvr/info-pagesvr     6405/tcp  # Info - Page Server<BR>, info-pagesvr<br><br><br>
info-pagesvr             6405/udp  # Info - Page Server<BR>
info-processor/info-processvr     6406/tcp  # Info - Processor<BR>, info-processvr<br><br><br>
info-processor           6406/udp  # Info - Processor<BR>
skip-cert-recv           6455/tcp  # skip-cert-recv<br><br>skip certificate receive<br>
skip-cert-recv           6455/udp  # SKIP Certificate Receive<BR>
skip-cert-send           6456/tcp  # SKIP Certificate Send<BR>
                         /udp  # 
lvision-lm               6471/tcp  # LVision License Manager<BR>
lvision-lm               6471/udp  # LVision License Manager<BR>
netscape                 6498/tcp  # Netscape Audio-Conferencing<BR>Note: Also see tcp 6502 &amp; udp 2327 <BR> 
                         /udp  # 
cooltalk                 6499/tcp  # CoolTalk Voice Comm Protocol<BR>
                         /udp  # 
boks                     6500/tcp  # BoKS Master<BR>
boks                     6500/udp  # BoKS Master<BR>
boks_servc               6501/tcp  # BoKS Servc<BR>
boks_servc               6501/udp  # BoKS Servc<BR>
netscape/boks_servm      6502/tcp  # Netscape Audio-Conferencing<BR>Note: Also see tcp 6498 &amp; udp 2327 <BR> , BoKS Servm<BR>
boks_servm               6502/udp  # BoKS Servm<BR>
boks_clntd               6503/tcp  # BoKS Clntd<BR>
boks_clntd               6503/udp  # BoKS Clntd<BR>
badm_priv                6505/tcp  # BoKS Admin Private Port<BR>
badm_priv                6505/udp  # BoKS Admin Private Port<BR>
badm_pub                 6506/tcp  # BoKS Admin Public Port<BR>
badm_pub                 6506/udp  # BoKS Admin Public Port<BR>
bdir_priv                6507/tcp  # BoKS Dir Server, Private Port<BR>
bdir_priv                6507/udp  # BoKS Dir Server, Private Port<BR>
bdir_pub                 6508/tcp  # BoKS Dir Server, Public Port<BR>
bdir_pub                 6508/udp  # BoKS Dir Server, Public Port<BR>
apc-tcp-udp-1            6547/tcp  # apc-tcp-udp-1<BR>
apc-tcp-udp-1            6547/udp  # apc-tcp-udp-1<BR>
apc-tcp-udp-2            6548/tcp  # apc-tcp-udp-2<BR>
apc-tcp-udp-2            6548/udp  # apc-tcp-udp-2<BR>
apc-tcp-udp-3            6549/tcp  # apc-tcp-udp-3<BR>
apc-tcp-udp-3            6549/udp  # apc-tcp-udp-3<BR>
fg-sysupdate             6550/tcp  # fg-sysupdate<BR>
fg-sysupdate             6550/udp  # fg-sysupdate<BR>
xdsxdm                   6558/tcp  # xdsxdm<BR>
xdsxdm                   6558/udp  # xdsxdm<BR>
circ                     6660/tcp  # Common for IRCD<BR>
circ                     6660/udp  # Common for IRCD<BR>
ircu                     6665/tcp  # IRCU<BR>
ircu                     6665/udp  # IRCU<BR>
                         /tcp  # 
nirc/ircu                6667/udp  # IRC backbone<BR><br> Control port for IRC. Client data exchange sets up on random-high udp port, similar to talk/ntalk. <BR> <br> Trojanized IRC Server source code exists in wild; beware or your source! <BR> , ircu<br><br>ircu<br>
circ                     6668/tcp  # Common for IRCD<BR>
circ/ircu                6668/udp  # Common for IRCD<BR>, ircu<br><br>ircu<br>
irc/vocaltec-gold        6670/tcp  # Internet Chat Relay<BR>, Vocaltec Global Online Directory<BR><br> Video-Teleconferencing. Also uses tcp 1490 &amp; 25793, tcp/udp 22555. <BR> 
vocaltec-gold            6670/udp  # Vocaltec Global Online Directory<BR><br> Video-Teleconferencing. Also uses tcp 1490 &amp; 25793, tcp/udp 22555. <BR> 
vision_server            6672/tcp  # vision_server<BR>
vision_server            6672/udp  # vision_server<BR>
vision_elmd              6673/tcp  # vision_elmd<BR>
vision_elmd              6673/udp  # vision_elmd<BR>
irc                      6680/tcp  # Internet Chat Relay<BR>
                         /udp  # 
winmx                    6699/tcp  # WinMx, Napster
winmx                    6699/udp  # WinMx, Napster
kti-icad-srvr            6701/tcp  # KTI/ICAD Nameserver<BR>
kti-icad-srvr            6701/udp  # KTI/ICAD Nameserver<BR>
subsevel-infection       6711/tcp  # SubSevel Infection Port<BR><br> One of the known SubSeven tcp control ports. Others include tcp 1243, 6712, 6713, 6776. Default is tcp 27374. <BR> 
                         /udp  # 
subsevel-infection       6712/tcp  # SubSevel Infection Port<BR><br> One of the known SubSeven tcp control ports. Others include tcp 1243, 6711, 6713, 6776. Default is tcp 27374. <BR> 
                         /udp  # 
subsevel-infection       6713/tcp  # SubSevel Infection Port<BR><br> One of the known SubSeven tcp control ports. Others include tcp 1243, 6711, 6712, 6776. Default is tcp 27374. <BR> 
                         /udp  # 
subsevel-infection       6776/tcp  # SubSevel Infection Port<BR><br> One of the known SubSeven tcp control ports. Others include tcp 1243, 6711, 6712, 6713. Default is tcp 27374. <BR> 
                         /udp  # 
hnmp                     6790/tcp  # HNMP<BR>
hnmp                     6790/udp  # HNMP<BR>
ambit-lm                 6831/tcp  # ambit-lm<BR>
ambit-lm                 6831/udp  # ambit-lm<BR>
netmo-default            6841/tcp  # Netmo Default<BR>
netmo-default            6841/udp  # Netmo Default<BR>
netmo-http               6842/tcp  # Netmo HTTP<BR>
netmo-http               6842/udp  # Netmo HTTP<BR>
iccrushmore              6850/tcp  # ICC RushMore<BR>
iccrushmore              6850/udp  # ICC RushMore<BR>
jmact3                   6961/tcp  # JMACT3<BR>
jmact3                   6961/udp  # JMACT3<BR>
jmevt2                   6962/tcp  # JMACT2<BR>
jmevt2                   6962/udp  # JMACT2<BR>
swismgr1                 6963/tcp  # SWIS Manager 1<BR>
swismgr1                 6963/udp  # SWIS Manager 1<BR>
swismgr2                 6964/tcp  # SWIS Manager 2<BR>
swismgr2                 6964/udp  # SWIS Manager 2<BR>
swistrap                 6965/tcp  # SWIS Trap<BR>
swistrap                 6965/udp  # SWIS Trap<BR>
swispol                  6966/tcp  # SWIS Poll<BR>
swispol                  6966/udp  # SWIS Poll<BR>
acmsoda                  6969/tcp  # acmsoda<BR>
acmsoda                  6969/udp  # acmsoda<BR>
                         /tcp  # 
real-audio-data          6970/udp  # RealAudio Data Streaming Ports<BR><br> RealAudio data streaming port range. RealAudio server dynamically selects udp port in this range to send client it's audio request. Server contol port is tcp 7070. <BR> 
iatp-highpri             6998/tcp  # IATP-highPri<BR>
iatp-highpri             6998/udp  # IATP-highPri<BR>
iatp-normalpri           6999/tcp  # IATP-normalPri<BR>
iatp-normalpri           6999/udp  # IATP-normalPri<BR>
afs3-fileserver          7000/tcp  # file server itself<BR>
afs3-fileserver/vdo-live/afs3-fileserver     7000/udp  # file server itself<BR>, VDO-Live Control Port<BR><br> Server port for client VDO-Live connections. Video datastream is to client's udp 7001. <BR> , afs3-fileserver<br><br>afs fileserver, file server itself<br>
afs3-callback            7001/tcp  # callbacks to cache managers, afs callback server
afs3-callback            7001/udp  # callbacks to cache managers, afs callback server
afs3-prserver            7002/tcp  # users &amp; groups database<BR>
afs3-prserver/afs3-prserver     7002/udp  # users &amp; groups database<BR>, afs3-prserver<br><br>afs protection server, users & groups database<br>
afs3-vlserver            7003/tcp  # volume location database<BR>
afs3-vlserver/afs3-vlserver     7003/udp  # volume location database<BR>, afs3-vlserver<br><br>afs volumelocation server, volume location database<br>
afs3-kaserver            7004/tcp  # AFS/Kerberos authentication service<BR>
afs3-kaserver/afs3-kaserver     7004/udp  # AFS/Kerberos authentication service<BR>, afs3-kaserver<br><br>afs kerberos authenication server, afs/kerberos authentication service<br>
afs3-volser              7005/tcp  # volume managment server<BR>
afs3-volser/afs3-volser     7005/udp  # volume managment server<BR>, afs3-volser<br><br>afs volume server, volume managment server<br>
afs3-errors              7006/tcp  # error interpretation service<BR>
afs3-errors/afs3-errors     7006/udp  # error interpretation service<BR>, afs3-errors<br><br>afs error server ?, error interpretation service<br>
afs3-bos                 7007/tcp  # basic overseer process<BR>
afs3-bos/afs3-bos        7007/udp  # basic overseer process<BR>, afs3-bos<br><br>afs basic over-see server ?, basic overseer process<br>
afs3-update              7008/tcp  # server-to-server updater<BR>
afs3-update/afs3-update     7008/udp  # server-to-server updater<BR>, afs3-update<br><br>server-to-server updater, ?<br>
afs3-rmtsys              7009/tcp  # Remote Cache Manager Service<BR>
afs3-rmtsys/afs3-rmtsys     7009/udp  # Remote Cache Manager Service<BR>, afs3-rmtsys<br><br>remote cache manager service, ?<br>
ups-onlinet              7010/tcp  # Onlinet Uninterruptable Power Supplies<BR>
ups-onlinet              7010/udp  # Onlinet Uninterruptable Power Supplies<BR>
talon-disc               7011/tcp  # Talon Discovery Port<BR>
talon-disc               7011/udp  # Talon Discovery Port<BR>
talon-engine             7012/tcp  # Talon Engine<BR>
talon-engine             7012/udp  # Talon Engine<BR>
dpserve                  7020/tcp  # DP Serve<BR>
dpserve                  7020/udp  # DP Serve<BR>
dpserveadmin             7021/tcp  # DP Serve Admin<BR>
dpserveadmin             7021/udp  # DP Serve Admin<BR>
arcp/real-audio-control     7070/tcp  # ARCP<BR>, RealAudio Contol Port<BR><br> Server control port for RealAudio. Client rqsts are answered with audio data stream on dynamic UDP ports in 6970-7170 range. <BR> 
arcp                     7070/udp  # ARCP<BR>
lazy-ptop                7099/tcp  # lazy-ptop<BR>
lazy-ptop                7099/udp  # lazy-ptop<BR>
fs                       7100/tcp  # X Font Service<BR><br> Required if host provids X-windows sessions to remote clients. May also be needed to support localhost GUI (depends on OS version). <BR> 
fs/font-service          7100/udp  # X Font Service<BR><br> Required if host provids X-windows sessions to remote clients. May also be needed to support localhost GUI (depends on OS version). <BR> , font-service<br><br>x font service<br>
virprot-lm               7121/tcp  # Virtual Prototypes License Manager<BR>
virprot-lm               7121/udp  # Virtual Prototypes License Manager<BR>
clutild                  7174/tcp  # Clutild<BR>
clutild                  7174/udp  # Clutild<BR>
fodms                    7200/tcp  # FODMS FLIP<BR>
fodms                    7200/udp  # FODMS FLIP<BR>
dlip                     7201/tcp  # DLIP<BR>
dlip                     7201/udp  # DLIP<BR>
roadrunner               7283/tcp  # RoadRunner Cable Modem Logon<BR><br> RoadRunner cable modem logon port, uses Toshiba's Auth Service (TAS). <BR> 
                         /udp  # 
swx/swx                  7300/tcp  # Swiss Exchange<BR>, swx<br><br>the swiss exchange<br>
swx                      7300/udp  # Swiss Exchange<BR>
winqedit                 7395/tcp  # winqedit<BR>
winqedit                 7395/udp  # winqedit<BR>
pmdmgr                   7426/tcp  # OpenView DM Postmaster Manager<BR>
pmdmgr                   7426/udp  # OpenView DM Postmaster Manager<BR>
oveadmgr                 7427/tcp  # OpenView DM Event Agent Manager<BR>
oveadmgr                 7427/udp  # OpenView DM Event Agent Manager<BR>
ovladmgr                 7428/tcp  # OpenView DM Log Agent Manager<BR>
ovladmgr                 7428/udp  # OpenView DM Log Agent Manager<BR>
opi-sock                 7429/tcp  # OpenView DM rqt communication<BR>
opi-sock                 7429/udp  # OpenView DM rqt communication<BR>
xmpv7                    7430/tcp  # OpenView DM xmpv7 api pipe<BR>
xmpv7                    7430/udp  # OpenView DM xmpv7 api pipe<BR>
pmd                      7431/tcp  # OpenView DM ovc/xmpv3 api pipe<BR>
pmd                      7431/udp  # OpenView DM ovc/xmpv3 api pipe<BR>
faximum                  7437/tcp  # Faximum<BR>
faximum                  7437/udp  # Faximum<BR>
telops-lmd               7491/tcp  # telops-lmd<BR>
telops-lmd               7491/udp  # telops-lmd<BR>
pafec-lm                 7511/tcp  # pafec-lm<BR>
pafec-lm                 7511/udp  # pafec-lm<BR>
nta-ds                   7544/tcp  # FlowAnalyzer DisplayServer<BR>
nta-ds                   7544/udp  # FlowAnalyzer DisplayServer<BR>
nta-us                   7545/tcp  # FlowAnalyzer UtilityServer<BR>
nta-us                   7545/udp  # FlowAnalyzer UtilityServer<BR>
vsi-omega                7566/tcp  # VSI Omega<BR>
vsi-omega                7566/udp  # VSI Omega<BR>
aries-kfinder            7570/tcp  # Aries Kfinder<BR>
aries-kfinder            7570/udp  # Aries Kfinder<BR>
sun-lm                   7588/tcp  # Sun License Manager<BR>
sun-lm                   7588/udp  # Sun License Manager<BR>
CU-SeeMe-srv             7648/tcp  # CU-SeeMe Server Ports<BR><br> Server control port for CU-SeeMe. Client contact port is tcp 7649. Data stream is over udp ports 7648-7652, and 24032. <BR> 
CU-SeeMe/CU-SeeMe-srv/cucme-1     7648/udp  # CU-SeeMe video, audio, and chat<BR>, CU-SeeMe Server Ports<BR><br> Server control port for CU-SeeMe. Client contact port is tcp 7649. Data stream is over udp ports 7648-7652, and 24032. <BR> , cucme-1<br><br>cucme live video/audio server<br>
pmdfmgt                  7633/tcp  # PMDF Manager<BR>
pmdfmgt                  7633/udp  # PMDF Manager<BR>
CU-SeeMe-clnt            7649/tcp  # CU-SeeMe Client Ports<BR><br> Client contact port for CU-SeeMe. Server port is tcp 7648. Data stream is over udp ports 7648-7652, and 24032. <BR> 
CU-SeeMe-clnt/cucme-2     7649/udp  # CU-SeeMe Client Ports<BR><br> Client contact port for CU-SeeMe. Server port is tcp 7648. Data stream is over udp ports 7648-7652, and 24032. <BR> , cucme-2<br><br>cucme live video/audio server<br>
                         /tcp  # 
udpcmd                   7666/udp  # UDP-Shell Backdoor (AKA: udpsh)<BR><br> A udp-based backdoor shell program. Once planted, remote intruder connects, receives root-level shell, and controls host with 800-byte udp pkts. Popular because udp scanning is laborious; less chance of detection by security scanners. <BR> <br> Open port indicates likely root-level intrusion. Grep processes for "udpcmd" daemon. <BR> 
cbt/eggdrop              7777/tcp  # cbt<BR>, Common for eggdrop bot<BR>
cbt/eggdrop              7777/udp  # cbt<BR>, Common for eggdrop bot<BR>
accu-lmgr                7781/tcp  # accu-lmgr<BR>
accu-lmgr                7781/udp  # accu-lmgr<BR>
t2-drm                   7932/tcp  # Tier 2 Data Resource Manager<BR>
t2-drm                   7932/udp  # Tier 2 Data Resource Manager<BR>
t2-brm                   7933/tcp  # Tier 2 Business Rules Manager<BR>
t2-brm                   7933/udp  # Tier 2 Business Rules Manager<BR>
supercell                7967/tcp  # Supercell<BR>
supercell                7967/udp  # Supercell<BR>
quest-vista              7980/tcp  # Quest Vista<BR>
quest-vista              7980/udp  # Quest Vista<BR>
irdmi2                   7999/tcp  # iRDMI2<BR>
irdmi2                   7999/udp  # iRDMI2<BR>
irdmi                    8000/tcp  # iRDMI<BR>
irdmi                    8000/udp  # iRDMI<BR>
vcom-tunnel              8001/tcp  # VCOM Tunnel<BR>
vcom-tunnel              8001/udp  # VCOM Tunnel<BR>
rcgi/teradataordbms      8002/tcp  # Perl.nlm port<BR><br> Perl.nlm port on NetWare v4.1 web servers. If reachable, attacker can access and execute perl scripts on the server. <BR> , teradataordbms<br><br>teradata ordbms<br>
teradataordbms           8002/udp  # teradataordbms<br><br>teradata ordbms<br>
http-alt                 8008/tcp  # HTTP Alternative<BR>
http-alt                 8008/udp  # HTTP Alternative<BR>
wingate                  8010/tcp  # Wingate Logfile (Deerfield)<BR><br> Wingate Logfile on v2.1 Wingate servers. <BR> Security Concerns: Listens for HTTP connects on tcp 8080. Open HTTP session to this logfile port may provide dir listing of Wingate's drive. To block this, config GateKeeper's "LogFile Service Bindings" to not allow inbound connections. Also config WinGate server to deny all but trusted IPs. <BR> 
wingate                  8010/udp  # Wingate Logfile (Deerfield)<BR><br> Wingate Logfile on v2.1 Wingate servers. <BR> Security Concerns: Listens for HTTP connects on tcp 8080. Open HTTP session to this logfile port may provide dir listing of Wingate's drive. To block this, config GateKeeper's "LogFile Service Bindings" to not allow inbound connections. Also config WinGate server to deny all but trusted IPs. <BR> 
pro-ed                   8032/tcp  # ProEd<BR>
pro-ed                   8032/udp  # ProEd<BR>
mindprint                8033/tcp  # MindPrint<BR>
mindprint                8033/udp  # MindPrint<BR>
http-alt                 8080/tcp  # HTTP Alternative<BR>
http-alt/http-alt        8080/udp  # HTTP Alternative<BR>, http-alt<br><br>http alternate (see port 80)<br>
blackice-logon           8081/tcp  # BlackIce Login<BR><br> Network admin port for BlackIce's "Network Ice" host-based firewall/intrusion detection program. <BR> Security Concerns: <BR> - May have shipped with default logon of "iceman
                         /udp  # 
blackice-alerts          8082/tcp  # BlackIce Alerts<BR><br> Alerting port for BlackIce's "Network Ice" host-based firewall/intrusion detection program. See Security Concerns above (8081). <BR> 
                         /udp  # 
patrol                   8160/tcp  # 
patrol                   8160/udp  # 
patrol-snmp              8161/tcp  # Patrol SNMP<BR>
patrol-snmp              8161/udp  # Patrol SNMP<BR>
trivnet1                 8200/tcp  # TRIVNET<BR>
trivnet1                 8200/udp  # TRIVNET<BR>
trivnet2                 8201/tcp  # TRIVNET<BR>
trivnet2                 8201/udp  # TRIVNET<BR>
lm-perfworks             8204/tcp  # LM Perfworks<BR>
lm-perfworks             8204/udp  # LM Perfworks<BR>
lm-instmgr               8205/tcp  # LM Instmgr<BR>
lm-instmgr               8205/udp  # LM Instmgr<BR>
lm-dta                   8206/tcp  # LM Dta<BR>
lm-dta                   8206/udp  # LM Dta<BR>
lm-sserver               8207/tcp  # LM Sserver<BR>
lm-sserver               8207/udp  # LM Sserver<BR>
lm-webwatcher            8208/tcp  # LM Webwatcher<BR>
lm-webwatcher            8208/udp  # LM Webwatcher<BR>
server-find              8351/tcp  # Server Find<BR>
server-find              8351/udp  # Server Find<BR>
cruise-enum              8376/tcp  # Cruise ENUM<BR>
cruise-enum              8376/udp  # Cruise ENUM<BR>
cruise-swroute           8377/tcp  # Cruise SWROUTE<BR>
cruise-swroute           8377/udp  # Cruise SWROUTE<BR>
cruise-config            8378/tcp  # Cruise CONFIG<BR>
cruise-config            8378/udp  # Cruise CONFIG<BR>
cruise-diags             8379/tcp  # Cruise DIAGS<BR>
cruise-diags             8379/udp  # Cruise DIAGS<BR>
cruise-update            8380/tcp  # Cruise UPDATE<BR>
cruise-update            8380/udp  # Cruise UPDATE<BR>
cvd                      8400/tcp  # cvd<BR>
cvd                      8400/udp  # cvd<BR>
sabarsd                  8401/tcp  # sabarsd<BR>
sabarsd                  8401/udp  # sabarsd<BR>
abarsd                   8402/tcp  # abarsd<BR>
abarsd                   8402/udp  # abarsd<BR>
admind                   8403/tcp  # admind<BR>
admind                   8403/udp  # admind<BR>
npmp                     8450/tcp  # npmp<BR>
npmp                     8450/udp  # npmp<BR>
vp2p                     8473/tcp  # Virtual Point-to-Point<BR>
vp2p                     8473/udp  # Virtual Point-to-Point<BR>
rtsp-alt                 8554/tcp  # RTSP Alternate (alt to port 554)<BR>
rtsp-alt                 8554/udp  # RTSP Alternate (alt to port 554)<BR>
netscape-adm             8649/tcp  # Netscape Web Server Admin Mgmt<BR>
                         /udp  # 
ibus                     8733/tcp  # iBus<BR>
ibus                     8733/udp  # iBus<BR>
mc-appserver             8763/tcp  # MC App Server<BR>
mc-appserver             8763/udp  # MC App Server<BR>
ultraseek-http           8765/tcp  # Ultraseek HTTP<BR>
ultraseek-http           8765/udp  # Ultraseek HTTP<BR>
truecm                   8804/tcp  # truecm<BR>
truecm                   8804/udp  # truecm<BR>
cddbp-alt                8880/tcp  # CDDBP<BR>
cddbp-alt                8880/udp  # CDDBP<BR>
ddi-tcp-1                8888/tcp  # NewsEDGE server TCP (TCP 1)<BR>
ddi-tcp-1/ddi-udp-1      8888/udp  # NewsEDGE server TCP (TCP 1)<BR>, ddi-udp-1<br><br>newsedge server udp (udp 1)<br>
ddi-tcp-2                8889/tcp  # Desktop Data TCP 1<BR>
ddi-tcp-2/ddi-udp-2      8889/udp  # Desktop Data TCP 1<BR>, ddi-udp-2<br><br>newsedge server broadcast<br>
ddi-tcp-3                8890/tcp  # Desktop Data TCP 2<BR>
ddi-tcp-3/ddi-udp-3      8890/udp  # Desktop Data TCP 2<BR>, ddi-udp-3<br><br>newsedge client broadcast<br>
ddi-tcp-4                8891/tcp  # Desktop Data TCP 3: NESS application<BR>
ddi-tcp-4/ddi-udp-4      8891/udp  # Desktop Data TCP 3: NESS application<BR>, ddi-udp-4<br><br>desktop data udp 3: ness application<br>
ddi-tcp-5                8892/tcp  # Desktop Data TCP 4: FARM product<BR>
ddi-tcp-5/ddi-udp-5      8892/udp  # Desktop Data TCP 4: FARM product<BR>, ddi-udp-5<br><br>desktop data udp 4: farm product<br>
ddi-tcp-6                8893/tcp  # Desktop Data TCP 5: NewsEDGE/Web App<BR>
ddi-tcp-6/ddi-udp-6      8893/udp  # Desktop Data TCP 5: NewsEDGE/Web App<BR>, ddi-udp-6<br><br>desktop data udp 5: newsedge/web application<br>
ddi-tcp-7                8894/tcp  # Desktop Data TCP 6: COAL application<BR>
ddi-tcp-7/ddi-udp-7      8894/udp  # Desktop Data TCP 6: COAL application<BR>, ddi-udp-7<br><br>desktop data udp 6: coal application<br>
jmb-cds1                 8900/tcp  # JMB-CDS 1<BR>
jmb-cds1                 8900/udp  # JMB-CDS 1<BR>
jmb-cds2                 8901/tcp  # JMB-CDS 2<BR>
jmb-cds2                 8901/udp  # JMB-CDS 2<BR>
cslistener               9000/tcp  # Cslistener<BR>
cslistener               9000/udp  # Cslistener<BR>
kastenxpipe              9001/tcp  # KastenX Pipe<BR>
kastenxpipe              9001/udp  # KastenX Pipe<BR>
sctp                     9006/tcp  # SCTP<BR>
sctp                     9006/udp  # SCTP<BR>
websm/CiscoSecure        9090/tcp  # WebSM<BR>, CiscoSecure<BR><br> Web server frontend for CiscoSecure. <BR> 
websm/websm              9090/udp  # WebSM<BR>, websm<br><br>websm<br>
CiscoSecure              9091/tcp  # CiscoSecure<BR><br> Web server frontend for CiscoSecure. <BR> 
                         /udp  # 
netlock1                 9160/tcp  # NetLOCK1<BR>
netlock1                 9160/udp  # NetLOCK1<BR>
netlock2                 9161/tcp  # NetLOCK2<BR>
netlock2                 9161/udp  # NetLOCK2<BR>
netlock3                 9162/tcp  # NetLOCK3<BR>
netlock3                 9162/udp  # NetLOCK3<BR>
netlock4                 9163/tcp  # NetLock4<BR>
netlock4                 9163/udp  # NetLock4<BR>
netlock5                 9164/tcp  # NetLOCK5<BR>
netlock5                 9164/udp  # NetLOCK5<BR>
wap-wsp                  9200/tcp  # WAP Connectionless Session Service<BR>
wap-wsp                  9200/udp  # WAP Connectionless Session Service<BR>
wap-wsp-wtp              9201/tcp  # WAP Session Service<BR>
wap-wsp-wtp              9201/udp  # WAP Session Service<BR>
wap-wsp-s                9202/tcp  # WAP Secure Connectionless Session Service<BR>
wap-wsp-s                9202/udp  # WAP Secure Connectionless Session Service<BR>
wap-wsp-wtp-s            9203/tcp  # WAP Secure Session Service<BR>
wap-wsp-wtp-s            9203/udp  # WAP Secure Session Service<BR>
wap-wsp-vcard/wap-vcard     9204/tcp  # WAP vCard<BR>, wap-vcard<br><br>wap vcard<br>
wap-wsp-vcard/wap-vcard     9204/udp  # WAP vCard<BR>, wap-vcard<br><br>wap vcard<br>
wap-wsp-vcal/wap-vcal     9205/tcp  # WAP vCal<BR>, wap-vcal<br><br>wap vcal<br>
wap-wsp-vcal/wap-vcal     9205/udp  # WAP vCal<BR>, wap-vcal<br><br>wap vcal<br>
wap-wsp-vcard-s/wap-vcard-s     9206/tcp  # WAP vCard Secure<BR>, wap-vcard-s<br><br>wap vcard secure<br>
wap-wsp-vcard-s/wap-vcard-s     9206/udp  # WAP vCard Secure<BR>, wap-vcard-s<br><br>wap vcard secure<br>
wap-wsp-vcal-s/wap-vcal-s     9207/tcp  # WAP vCal Secure<BR>, wap-vcal-s<br><br>wap vcal secure<br>
wap-wsp-vcal-s/wap-vcal-s     9207/udp  # WAP vCal Secure<BR>, wap-vcal-s<br><br>wap vcal secure<br>
quibase/guibase          9321/tcp  # quibase<BR>, guibase<br><br>guibase<br>
quibase/guibase          9321/udp  # quibase<BR>, guibase<br><br>guibase<br>
mpidcmgr                 9343/tcp  # Mpidcmgr<BR>
mpidcmgr                 9343/udp  # Mpidcmgr<BR>
mphlpdmc                 9344/tcp  # Mphlpdmc<BR>
mphlpdmc                 9344/udp  # Mphlpdmc<BR>
fjdmimgr                 9374/tcp  # fjdmimgr<BR>
fjdmimgr                 9374/udp  # fjdmimgr<BR>
fjinvmgr                 9396/tcp  # fjinvmgr<BR>
fjinvmgr                 9396/udp  # fjinvmgr<BR>
mpidcagt                 9397/tcp  # mpidcagt<BR>
mpidcagt                 9397/udp  # mpidcagt<BR>
ismserver                9500/tcp  # ismserver<BR>
ismserver                9500/udp  # ismserver<BR>
man                      9535/tcp  # man<BR>
man                      9535/udp  # man<BR>
w                        9536/tcp  # w<BR>
                         /udp  # 
mantst                   9537/tcp  # Remote man server, testing<BR>
                         /udp  # 
msgsys                   9594/tcp  # Message System<BR>
msgsys                   9594/udp  # Message System<BR>
pds                      9595/tcp  # Ping Discovery Service<BR>
pds                      9595/udp  # Ping Discovery Service<BR>
rasadv                   9753/tcp  # rasadv<BR>
rasadv                   9753/udp  # rasadv<BR>
sd                       9876/tcp  # Session Director<BR>
sd                       9876/udp  # Session Director<BR>
cyborg-systems           9888/tcp  # CYBORG Systems<BR>
cyborg-systems           9888/udp  # CYBORG Systems<BR>
monkeycom                9898/tcp  # MonkeyCom<BR>
monkeycom                9898/udp  # MonkeyCom<BR>
cisco-acs/iua            9900/tcp  # CiscoSecure Access Control Server (ACS)<BR><br> Cisco alert states unauth remote users can read/write to server's database. Block via ACS config, network blocking, or upgrade of ACS software. <BR> , iua<br><br>iua<br>
iua                      9900/udp  # iua<br><br>iua<br>
CiscoSecureDB            9901/tcp  # CiscoSecureDB<BR>
CiscoSecureDB            9901/udp  # CiscoSecureDB<BR>
domaintime               9909/tcp  # domaintime<BR>
domaintime               9909/udp  # domaintime<BR>
                         /tcp  # 
ivisit                   9943/udp  # ivisit Video-Teleconferencing<BR><br> Also uses udp 9945, 56768. <BR> 
                         /tcp  # 
ivisit                   9945/udp  # ivisit Video-Teleconferencing<BR><br> Also uses udp 9943, 56768. <BR> 
palace                   9992/tcp  # Palace Chat<BR>
palace                   9992/udp  # Palace Chat<BR>
cpalace/distinct32/pirc     9998/tcp  # Common Palace<BR>, Distinct32<BR>, Possible for IRCD<BR>
distinct32/pirc          9998/udp  # Distinct32<BR>, Possible for IRCD<BR>
Backdoor/distinct/onguard     9999/tcp  # Intruder Backdoor Port<BR><br> Internet-publicized hack to replace in.telnetd with modified version that starts up in debug mode. This makes it bind to tcp 9999 and execute /bin/sh instead of /bin/login. Also forks before executing shell, which means it will accept multiple simultaneous connects. <BR> , distinct<BR>, Lenel OnGuard HTTP License Administrator.
distinct                 9999/udp  # distinct<BR>
ndmp/bnews/Webmin/Cisco-NAT-T     10000/tcp  # Network Data Management Protocol<BR><br> Used to centrally control data backups. <BR> , bnews<BR>, , Cisco proprietary encapsulations for NAT transparency
ndmp/rscs0/Cisco-NAT-T     10000/udp  # Network Data Management Protocol<BR><br> Used to centrally control data backups. <BR> , rscs0<BR>, Cisco proprietary encapsulations for NAT transparency
queue                    10001/tcp  # queue<BR>
rscs1                    10001/udp  # rscs1<BR>
poker/rusers             10002/tcp  # poker<BR>, rusers<BR><br> The ruser udp broadcast will return list of logged on users on local network, plus when they logged in, current duratino of logon, and idle time. Can also be used for single probes. <BR> Security Concerns: Provides valuable info to attackers, such as usernames, logged on users on key servers, and which sessions are idle (ripe for hijack). <BR> <br> Disable rusers on all hosts. <BR> 
rscs2/rusers             10002/udp  # rscs2<BR>, rusers<BR><br> The ruser udp broadcast will return list of logged on users on local network, plus when they logged in, current duratino of logon, and idle time. Can also be used for single probes. <BR> Security Concerns: Provides valuable info to attackers, such as usernames, logged on users on key servers, and which sessions are idle (ripe for hijack). <BR> <br> Disable rusers on all hosts. <BR> 
gateway                  10003/tcp  # gateway<BR>
rscs3                    10003/udp  # rscs3<BR>
remp                     10004/tcp  # remp<BR>
rscs4                    10004/udp  # rscs4<BR>
stel                     10005/tcp  # stel<br><br>secure telnet<br>
rscs5                    10005/udp  # rscs5<BR>
                         /tcp  # 
rscs6                    10006/udp  # rscs6<BR>
mvs-capacity             10007/tcp  # MVS Capacity<BR>
rscs7/mvs-capacity       10007/udp  # rscs7<BR>, MVS Capacity<BR>
                         /tcp  # 
rscs8                    10008/udp  # rscs8<BR>
                         /tcp  # 
rscs9                    10009/udp  # rscs9<BR>
                         /tcp  # 
rscsa                    10010/udp  # rscsa<BR>
                         /tcp  # 
rscsb                    10011/udp  # rscsb<BR>
qmaster                  10012/tcp  # qmaster<BR>
qmaster                  10012/udp  # qmaster<BR>
amanda                   10080/tcp  # Amanda<BR>
amanda/amanda            10080/udp  # Amanda<BR>, amanda<br><br>amanda, amanda backup util, dump server control<br>
ganymede-endpt           10115/tcp  # Ganymede Endpoint<BR>
ganymede-endpt           10115/udp  # Ganymede Endpoint<BR>
blocks                   10288/tcp  # Blocks<BR>
blocks                   10288/udp  # Blocks<BR>
irisa                    11000/tcp  # IRISA<BR>
irisa                    11000/udp  # IRISA<BR>
metasys                  11001/tcp  # Metasys<BR>
metasys                  11001/udp  # Metasys<BR>
vce                      11111/tcp  # Viral Computing Environment (VCE)<BR>
vce                      11111/udp  # Viral Computing Environment (VCE)<BR>
atm-uhas                 11367/tcp  # ATM UHAS<BR>
atm-uhas                 11367/udp  # ATM UHAS<BR>
h323callsigalt           11720/tcp  # H.323 Call Signal Alternative<BR>
h323callsigalt           11720/udp  # H.323 Call Signal Alternative<BR>
entextxid/solaris-cluster     12000/tcp  # IBM Enterprise Extender SNA XID Exchange<BR>, Solaris Cluster v2.x opens this port. When enabled, remote attaker can read host's syslog and view cluster config info. If attacker has a local account, can create a symbolic link in /var/opt/SUNWcluster/fm/fmstatus/nfs/&lt;logicalhostname/status, then use "open hastat" command of the monitor daemon to view any file on the host.<BR>
entextxid/solaris-cluster     12000/udp  # IBM Enterprise Extender SNA XID Exchange<BR>, Solaris Cluster v2.x opens this port. When enabled, remote attaker can read host's syslog and view cluster config info. If attacker has a local account, can create a symbolic link in /var/opt/SUNWcluster/fm/fmstatus/nfs/&lt;logicalhostname/status, then use "open hastat" command of the monitor daemon to view any file on the host.<BR>
entextnetwk              12001/tcp  # IBM Enterprise Extender SNA COS Network Priority<BR>
entextnetwk              12001/udp  # IBM Enterprise Extender SNA COS Network Priority<BR>
entexthigh               12002/tcp  # IBM Enterprise Extender SNA COS Hi-Priority<BR>
entexthigh               12002/udp  # IBM Enterprise Extender SNA COS Hi-Priority<BR>
entextmed                12003/tcp  # IBM Enterprise Extender SNA COS Med-Priority<BR>
entextmed                12003/udp  # IBM Enterprise Extender SNA COS Med-Priority<BR>
entextlow                12004/tcp  # IBM Enterprise Extender SNA COS Low-Priority<BR>
entextlow                12004/udp  # IBM Enterprise Extender SNA COS Low-Priority<BR>
hivep                    12172/tcp  # HiveP<BR>
hivep                    12172/udp  # HiveP<BR>
NetBus-Cmd/NetBus        12345/tcp  # NetBus Command Port<BR><br> Command Port on original NetBus infections. See below (12346). <BR> , NetBus<br><br>netbus backdoor trojan<br>
                         /udp  # 
NetBus-Data/NetBus       12346/tcp  # NetBus Data Transfer Port<BR>Note: Data transfer port on original NetBus infections (Win9x &amp; NT hosts). On original NetBus, Command &amp; Data Tx ports were fixed. In second version (c1999), it's configurable. <BR> , NetBus<br><br>netbus backdoor trojan<br>
                         /udp  # 
webtheater               12468/tcp  # Web Theater Control Port<BR><br> Server port for Web Theater client requests. Server responds with multimedia data stream via UDP port (NFI). <BR> 
                         /udp  # 
tsaf                     12753/tcp  # tsaf port<BR>
tsaf                     12753/udp  # tsaf port<BR>
i-zipqd                  13160/tcp  # I-ZIPQD<BR>
i-zipqd                  13160/udp  # I-ZIPQD<BR>
bprd                     13720/tcp  # BPRD Protocol (Veritas NetBackup)<BR>
bprd                     13720/udp  # BPRD Protocol (Veritas NetBackup)<BR>
bpbrm                    13721/tcp  # BPBRM Protocol (Veritas NetBackup)<BR>
bpbrm                    13721/udp  # BPBRM Protocol (Veritas NetBackup)<BR>
bpjava-msvc              13722/tcp  # BP Java MSVC Protocol<BR>
bpjava-msvc              13722/udp  # BP Java MSVC Protocol<BR>
bpcd                     13782/tcp  # Veritas NetBackup<BR>
bpcd                     13782/udp  # Veritas NetBackup<BR>
vopied                   13783/tcp  # VOPIED Protocol<BR>
vopied                   13783/udp  # VOPIED Protocol<BR>
dsmcc-config             13818/tcp  # DSMCC Config<BR>
dsmcc-config             13818/udp  # DSMCC Config<BR>
dsmcc-session            13819/tcp  # DSMCC Session Messages<BR>
dsmcc-session            13819/udp  # DSMCC Session Messages<BR>
dsmcc-passthru           13820/tcp  # DSMCC Pass-Thru Messages<BR>
dsmcc-passthru           13820/udp  # DSMCC Pass-Thru Messages<BR>
dsmcc-download           13821/tcp  # DSMCC Download Protocol<BR>
dsmcc-download           13821/udp  # DSMCC Download Protocol<BR>
dsmcc-ccp                13822/tcp  # DSMCC Channel Change Protocol<BR>
dsmcc-ccp                13822/udp  # DSMCC Channel Change Protocol<BR>
itu-sccp-ss7             14001/tcp  # ITU SCCP (SS7)<BR>
itu-sccp-ss7             14001/udp  # ITU SCCP (SS7)<BR>
hotsync                  14237/tcp  # Palm Network Hotsync<BR>
                         /udp  # 
                         /tcp  # 
hotsync                  14238/udp  # Palm Network Hotsync<BR>
netserialext1            16360/tcp  # netserialext1<BR>
netserialext1            16360/udp  # netserialext1<BR>
netserialext2            16361/tcp  # netserialext2<BR>
netserialext2            16361/udp  # netserialext2<BR>
netserialext3            16367/tcp  # netserialext3<BR>
netserialext3            16367/udp  # netserialext3<BR>
netserialext4            16368/tcp  # netserialext4<BR>
netserialext4            16368/udp  # netserialext4<BR>
connected-ob             16384/tcp  # Connected On-Line Backup<BR><br> Host "wake up" daemon. Controller connects to this port on "sleeping" host, powers it completely up, and instructs it to send backup data to server. Includes encryption. <BR> 
                         /udp  # 
deslogin                 16661/tcp  # DESlogon backdoor<BR><br> Default port for "deslogin". Upon connect and correct username/password, user receives a DES-encrypted secure shell. <BR> 
                         /udp  # 
isode-dua                17007/tcp  # isode-dua<BR>
isode-dua                17007/udp  # isode-dua<BR>
chipper                  17219/tcp  # Chipper<BR>
chipper                  17219/udp  # Chipper<BR>
biimenu                  18000/tcp  # Beckman Instruments, Inc.<BR>
biimenu                  18000/udp  # Beckman Instruments, Inc.<BR>
opsec-cvp                18181/tcp  # OPSEC CVP<BR>
opsec-cvp                18181/udp  # OPSEC CVP<BR>
opsec-ufp                18182/tcp  # OPSEC UFP<BR>
opsec-ufp                18182/udp  # OPSEC UFP<BR>
ac-cluster               18463/tcp  # AC Cluster<BR>
ac-cluster               18463/udp  # AC Cluster<BR>
apc-necmp/liquid-audio     18888/tcp  # APC NECMP<BR>, Liquid Audio Control<BR>
apc-necmp/liquid-audio     18888/udp  # APC NECMP<BR>, Liquid Audio Control<BR>
                         /tcp  # 
liquid-audio             18889/udp  # Liquid Audio Data Streaming<BR>
keysrv/keysrvr           19283/tcp  # Key Server for SASSAFRAS<BR>, keysrvr<br><br>key server for sassafras<br>
keysrv/keysrvr           19283/udp  # Key Server for SASSAFRAS<BR>, keysrvr<br><br>key server for sassafras<br>
keyshadow                19315/tcp  # Key Shadow for SASSAFRAS<BR>
keyshadow                19315/udp  # Key Shadow for SASSAFRAS<BR>
hp-sco                   19410/tcp  # hp-sco<BR>
hp-sco                   19410/udp  # hp-sco<BR>
hp-sca                   19411/tcp  # hp-sca<BR>
hp-sca                   19411/udp  # hp-sca<BR>
jcp                      19541/tcp  # JCP Client<BR>
jcp                      19541/udp  # JCP Client<BR>
dnp/Usermin              20000/tcp  # DNP<BR>, 
dnp                      20000/udp  # DNP<BR>
netbus-cmd               20034/tcp  # Default port for NetBus v2.0<BR><br> NetBus is a program used to remotely control Win95/98 and NT hosts. It is a popular program used by attackers to subvert Microsoft hosts. <BR> 
                         /udp  # 
track                    20670/tcp  # Track<BR>
track                    20670/udp  # Track<BR>
                         /tcp  # 
FreeTel                  21300/udp  # FreeTel Voice Comm Protocol<BR>
vofr-gateway             21590/tcp  # VOFR Gateway<BR>
vofr-gateway             21590/udp  # VOFR Gateway<BR>
webphone                 21845/tcp  # webphone<BR>
webphone                 21845/udp  # webphone<BR>
netspeak-is              21846/tcp  # NetSpeak Corp. Directory Services<BR>
netspeak-is              21846/udp  # NetSpeak Corp. Directory Services<BR>
netspeak-cs              21847/tcp  # NetSpeak Corp. Connection Services<BR>
netspeak-cs              21847/udp  # NetSpeak Corp. Connection Services<BR>
netspeak-acd             21848/tcp  # NetSpeak Corp. Automatic Call Distro<BR>
netspeak-acd             21848/udp  # NetSpeak Corp. Automatic Call Distro<BR>
netspeak-cps             21849/tcp  # NetSpeak Corp. Credit Processing System<BR>
netspeak-cps             21849/udp  # NetSpeak Corp. Credit Processing System<BR>
snapenetio               22000/tcp  # SNAPenet IO<BR>
snapenetio               22000/udp  # SNAPenet IO<BR>
optocontrol              22001/tcp  # OptoControl<BR>
optocontrol              22001/udp  # OptoControl<BR>
wnn6                     22273/tcp  # wnn6<BR>
wnn6/wnn6                22273/udp  # wnn6<BR>, wnn6<br><br>wnn6<br>
vocaltec-wconf           22555/tcp  # Vocaltec Audio&amp;Doc Web Conferencing<BR><br> Video-Teleconferencing. Also uses tcp 1490, 6670, 25793; udp 22555. <BR> 
vocaltec-phone           22555/udp  # Vocaltec Internet Phone<BR><br> Video-Teleconferencing. Also uses tcp 1490, 6670, 25793; tcp 22555. <BR> 
aws-brf                  22800/tcp  # Telerate Info Platform LAN<BR>
aws-brf                  22800/udp  # Telerate Info Platform LAN<BR>
brf-gw                   22951/tcp  # Telerate Info Platform WAN<BR>
brf-gw                   22951/udp  # Telerate Info Platform WAN<BR>
med-ltp                  24000/tcp  # med-ltp<BR>
med-ltp                  24000/udp  # med-ltp<BR>
med-fsp-rx               24001/tcp  # med-fsp-rx<BR>
med-fsp-rx               24001/udp  # med-fsp-rx<BR>
med-fsp-tx               24002/tcp  # med-fsp-tx<BR>
med-fsp-tx               24002/udp  # med-fsp-tx<BR>
med-supp                 24003/tcp  # med-supp<BR>
med-supp                 24003/udp  # med-supp<BR>
med-ovw                  24004/tcp  # med-ovw<BR>
med-ovw                  24004/udp  # med-ovw<BR>
med-ci                   24005/tcp  # med-ci<BR>
med-ci                   24005/udp  # med-ci<BR>
med-net-svc              24006/tcp  # med-net-svc<BR>
med-net-svc              24006/udp  # med-net-svc<BR>
intel_rci                24386/tcp  # Intel RCI<BR>
intel_rci                24386/udp  # Intel RCI<BR>
icl-twobase1             25000/tcp  # icl-twobase1<BR>
icl-twobase1             25000/udp  # icl-twobase1<BR>
icl-twobase2             25001/tcp  # icl-twobase2<BR>
icl-twobase2             25001/udp  # icl-twobase2<BR>
icl-twobase3             25002/tcp  # icl-twobase3<BR>
icl-twobase3             25002/udp  # icl-twobase3<BR>
icl-twobase4             25003/tcp  # icl-twobase4<BR>
icl-twobase4             25003/udp  # icl-twobase4<BR>
icl-twobase5             25004/tcp  # icl-twobase5<BR>
icl-twobase5             25004/udp  # icl-twobase5<BR>
icl-twobase6             25005/tcp  # icl-twobase6<BR>
icl-twobase6             25005/udp  # icl-twobase6<BR>
icl-twobase7             25006/tcp  # icl-twobase7<BR>
icl-twobase7             25006/udp  # icl-twobase7<BR>
icl-twobase8             25007/tcp  # icl-twobase8<BR>
icl-twobase8             25007/udp  # icl-twobase8<BR>
icl-twobase9             25008/tcp  # icl-twobase9<BR>
icl-twobase9             25008/udp  # icl-twobase9<BR>
icl-twobase10            25009/tcp  # icl-twobase10<BR>
icl-twobase10            25009/udp  # icl-twobase10<BR>
telalert                 25378/tcp  # Telalert<BR>
                         /udp  # 
vocaltec-hos/vocaltec-hos     25793/tcp  # Vocaltec Address Server<BR><br> Video-Teleconferencing. Also uses tcp 1490, 6670, 22555; udp 22555. <BR> , vocaltec-hos<br><br>vocaltec address server<br>
vocaltec-hos             25793/udp  # vocaltec-hos<br><br>vocaltec address server<br>
webcam32                 25867/tcp  # Webcam32 (Kolban Webcam Software)<BR><br> v4.8.3 and below have buffer overflow that allows attacker to execute arbitrary commands on user's Win95/98 host. <BR> 
                         /udp  # 
quake                    26000/tcp  # quake<BR>
quake                    26000/udp  # quake<BR>
wnn6-ds                  26208/tcp  # wnn6-ds<BR>
wnn6-ds/wnn6-ds          26208/udp  # wnn6-ds<BR>, wnn6-ds<br><br>wnn6-ds<br>
flex-lm/flex-lm          27000/tcp  # Flex License Manager (1-10)<BR>, flex-lm<br><br>flex lm (1-10)<br>
flex-lm                  27000/udp  # Flex License Manager (1-10)<BR>
subsevel-infection       27374/tcp  # SubSevel Infection Port<BR><br> Default SubSeven tcp control ports. Others can include tcp 1243, 6711, 6712, 6713, &amp; 6776. <BR> 
                         /udp  # 
tw-auth-key              27999/tcp  # TW Auth/Key Distribution &amp; Attribute Cert Services<BR>
tw-auth-key/tw-auth-key     27999/udp  # TW Auth/Key Distribution &amp; Attribute Cert Services<BR>, tw-auth-key<br><br>attribute certificate services<br>
sockets-de-troje         30303/tcp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 5001, 50505. <BR> 
sockets-de-troje         30303/udp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 5001, 50505. <BR> 
pirc/eleet               31337/tcp  # Possible for IRCD<BR>, Intruder Programs!<BR><br> Port 31337 has long been popular for intruder programs. Consider any connection attempts to it highly suspicious! Common programs using it include: original Back Orifice (Win9x, NT) and socdmini (Unix). <BR> <br> "ELEET" is hackereze for "31337". <BR> 
pirc/eleet/BackOrifice     31337/udp  # Possible for IRCD<BR>, Intruder Programs!<BR><br> Port 31337 has long been popular for intruder programs. Consider any connection attempts to it highly suspicious! Common programs using it include: original Back Orifice (Win9x, NT) and socdmini (Unix). <BR> <br> "ELEET" is hackereze for "31337". <BR> , BackOrifice<br><br>cdc back orifice remote admin tool<br>
                         /tcp  # 
Hack-a-tack              31789/udp  # Hack-a-tack Backdoor<BR><br> Remote access login port using udp shell. <BR> 
filenet-tms              32768/tcp  # Filenet TMS<BR>
filenet-tms              32768/udp  # Filenet TMS<BR>
filenet-rpc              32769/tcp  # Filenet RPC<BR>
filenet-rpc              32769/udp  # Filenet RPC<BR>
filenet-nch              32770/tcp  # Filenet NCH<BR>
filenet-nch              32770/udp  # Filenet NCH<BR>
traceroute               33434/tcp  # traceroute use<BR>
traceroute               33434/udp  # traceroute use<BR>
kastenxpipe              36865/tcp  # KastenX Pipe<BR>
kastenxpipe              36865/udp  # KastenX Pipe<BR>
reachout                 43188/tcp  # reachout<BR>
reachout                 43188/udp  # reachout<BR>
rockwell-encap           44818/tcp  # Rockwell Encapsulation<BR>
rockwell-encap           44818/udp  # Rockwell Encapsulation<BR>
eba                      45678/tcp  # EBA PRISE<BR>
eba                      45678/udp  # EBA PRISE<BR>
netranger                45000/tcp  # NetRanger's Alert Traffic<BR><br> Used by NetRanger <BR> 
                         /udp  # 
dbbrowse                 47557/tcp  # Databeam Corporation<BR>
dbbrowse                 47557/udp  # Databeam Corporation<BR>
directplaysrvr           47624/tcp  # Direct Play Server<BR>
directplaysrvr           47624/udp  # Direct Play Server<BR>
ap                       47806/tcp  # ALC Protocol<BR>
ap                       47806/udp  # ALC Protocol<BR>
bacnet                   47808/tcp  # Building Automation &amp; Control Networks<BR>
bacnet                   47808/udp  # Building Automation &amp; Control Networks<BR>
nimcontroller            48000/tcp  # Nimbus Controller<BR>
nimcontroller            48000/udp  # Nimbus Controller<BR>
nimspooler               48001/tcp  # Nimbus Spooler<BR>
nimspooler               48001/udp  # Nimbus Spooler<BR>
nimhub                   48002/tcp  # Nimbus Hub<BR>
nimhub                   48002/udp  # Nimbus Hub<BR>
nimgtw                   48003/tcp  # Nimbus Gateway<BR>
nimgtw                   48003/udp  # Nimbus Gateway<BR>
sockets-de-troje         50505/tcp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 5001, 30303. <BR> 
sockets-de-troje         50505/udp  # Sockets de Trojie Backdoor<BR><br> Also infects tcp/udp 5000, 5001, 30303. <BR> 
dialpad                  51210/tcp  # Dialpad Telephony<BR><br> Also uses udp 51200 &amp; 51201. <BR> 
                         /udp  # 
                         /tcp  # 
ivisit                   56768/udp  # ivisit Video-Teleconferencing<BR><br> Also uses udp 9943, 9945. <BR> 
pcanywheredata/pcanywhere     65301/tcp  # pcAnywhere Data<BR><br> Default tcp port for v2.0 thru v7.51, plus CE. Versions v8+ on use tcp 5631 &amp; udp 5632. <BR> , pcanywhere<br><br><br>
                         /udp  # 
backdoor-port            65534/tcp  # Reported Backdoor<BR><br> Reported found on Linux hosts as a hacked backdoor, along with tcp 1049 (both open on same host). Little else known. <BR> 
                         /udp  # 
                         /tcp  # 
ufsd                     1008/udp  # ufsd<br><br><br>
amandaidx                10082/tcp  # amandaidx<br><br>amanda indexing<br>
                         /udp  # 
amidxtape                10083/tcp  # amidxtape<br><br>amanda tape indexing<br>
                         /udp  # 
                         /tcp  # 
sometimes-rpc1           1012/udp  # sometimes-rpc1<br><br>this is rstatd on my openbsd box<br>
nterm                    1026/tcp  # nterm<br><br>remote_login network_terminal<br>
                         /udp  # 
vfo                      1056/tcp  # vfo<br><br>vfo<br>
vfo                      1056/udp  # vfo<br><br>vfo<br>
xaudio                   1103/tcp  # xaudio<br><br>x audio server, xaserver	<br>
                         /udp  # 
msql                     1112/tcp  # msql<br><br>mini-sql server<br>
                         /udp  # 
supfiledbg               1127/tcp  # supfiledbg<br><br>sup debugging, for sup<br>
                         /udp  # 
tripwire                 1169/tcp  # tripwire<br><br>tripwire<br>
tripwire                 1169/udp  # tripwire<br><br>tripwire<br>
skkserv                  1178/tcp  # skkserv<br><br>skk (kanji input)<br>
                         /udp  # 
hp-webadmin              1188/tcp  # hp-webadmin<br><br>hp web admin<br>
hp-webadmin              1188/udp  # hp-webadmin<br><br>hp web admin<br>
msg                      1241/tcp  # msg<br><br>remote message server<br>
                         /udp  # 
intuitive-edge           1355/tcp  # intuitive-edge<br><br>intuitive edge<br>
intuitive-edge           1355/udp  # intuitive-edge<br><br>intuitive edge<br>
intel-rci-mp             16991/tcp  # intel-rci-mp<br><br>intel-rci-mp<br>
intel-rci-mp             16991/udp  # intel-rci-mp<br><br>intel-rci-mp<br>
opsec-sam                18183/tcp  # opsec-sam<br><br>opsec sam<br>
opsec-sam                18183/udp  # opsec-sam<br><br>opsec sam<br>
opsec-lea                18184/tcp  # opsec-lea<br><br>opsec lea<br>
opsec-lea                18184/udp  # opsec-lea<br><br>opsec lea<br>
opsec-omi                18185/tcp  # opsec-omi<br><br>opsec omi<br>
opsec-omi                18185/udp  # opsec-omi<br><br>opsec omi<br>
opsec-ela                18187/tcp  # opsec-ela<br><br>opsec ela<br>
opsec-ela                18187/udp  # opsec-ela<br><br>opsec ela<br>
ardusmul                 1835/tcp  # ardusmul<br><br>ardus multicast<br>
ardusmul                 1835/udp  # ardusmul<br><br>ardus multicast<br>
mc2studios               1899/tcp  # mc2studios<br><br>mc2studios<br>
mc2studios               1899/udp  # mc2studios<br><br>mc2studios<br>
hp-sessmon               19412/tcp  # hp-sessmon<br><br>hp-sessmon<br>
hp-sessmon               19412/udp  # hp-sessmon<br><br>hp-sessmon<br>
btx                      20005/tcp  # btx<br><br>xcept4 (interacts with german telekom's cept videotext service)<br>
                         /udp  # 
cfingerd                 2003/tcp  # cfingerd<br><br>gnu finger<br>
                         /udp  # 
ergolight                2109/tcp  # ergolight<br><br>ergolight<br>
ergolight                2109/udp  # ergolight<br><br>ergolight<br>
umsp                     2110/tcp  # umsp<br><br>umsp<br>
umsp                     2110/udp  # umsp<br><br>umsp<br>
                         /tcp  # 
dsatp                    2111/udp  # dsatp<br><br>dsatp<br>
                         /tcp  # 
idonix-metanet           2112/udp  # idonix-metanet<br><br>idonix metanet<br>
hsl-storm                2113/tcp  # hsl-storm<br><br>hsl storm<br>
hsl-storm                2113/udp  # hsl-storm<br><br>hsl storm<br>
newheights               2114/tcp  # newheights<br><br>newheights<br>
newheights               2114/udp  # newheights<br><br>newheights<br>
kdm                      2115/tcp  # kdm<br><br>kdm<br>
kdm                      2115/udp  # kdm<br><br>kdm<br>
ccowcmr                  2116/tcp  # ccowcmr<br><br>ccowcmr<br>
ccowcmr                  2116/udp  # ccowcmr<br><br>ccowcmr<br>
mentaclient              2117/tcp  # mentaclient<br><br>mentaclient<br>
mentaclient              2117/udp  # mentaclient<br><br>mentaclient<br>
mentaserver              2118/tcp  # mentaserver<br><br>mentaserver<br>
mentaserver              2118/udp  # mentaserver<br><br>mentaserver<br>
gsigatekeeper            2119/tcp  # gsigatekeeper<br><br>gsigatekeeper<br>
gsigatekeeper            2119/udp  # gsigatekeeper<br><br>gsigatekeeper<br>
                         /tcp  # 
qencp                    2120/udp  # qencp<br><br>quick eagle networks cp<br>
scientia-ssdb            2121/tcp  # scientia-ssdb<br><br>scientia-ssdb<br>
scientia-ssdb            2121/udp  # scientia-ssdb<br><br>scientia-ssdb<br>
caupc-remote             2122/tcp  # caupc-remote<br><br>caupc remote control<br>
caupc-remote             2122/udp  # caupc-remote<br><br>caupc remote control<br>
gtp-control              2123/tcp  # gtp-control<br><br>gtp-control plane (3gpp)<br>
gtp-control              2123/udp  # gtp-control<br><br>gtp-control plane (3gpp)<br>
elatelink                2124/tcp  # elatelink<br><br>elatelink<br>
elatelink                2124/udp  # elatelink<br><br>elatelink<br>
lockstep                 2125/tcp  # lockstep<br><br>lockstep<br>
lockstep                 2125/udp  # lockstep<br><br>lockstep<br>
pktcable-cops            2126/tcp  # pktcable-cops<br><br>pktcable-cops<br>
pktcable-cops            2126/udp  # pktcable-cops<br><br>pktcable-cops<br>
index-pc-wb              2127/tcp  # index-pc-wb<br><br>index-pc-wb<br>
index-pc-wb              2127/udp  # index-pc-wb<br><br>index-pc-wb<br>
net-steward              2128/tcp  # net-steward<br><br>net steward control<br>
net-steward              2128/udp  # net-steward<br><br>net steward control<br>
cs-live                  2129/tcp  # cs-live<br><br>cs-live.com<br>
cs-live                  2129/udp  # cs-live<br><br>cs-live.com<br>
swc-xds                  2130/tcp  # swc-xds<br><br>swc-xds<br>
swc-xds                  2130/udp  # swc-xds<br><br>swc-xds<br>
avantageb2b              2131/tcp  # avantageb2b<br><br>avantageb2b<br>
avantageb2b              2131/udp  # avantageb2b<br><br>avantageb2b<br>
avail-epmap              2132/tcp  # avail-epmap<br><br>avail-epmap<br>
avail-epmap              2132/udp  # avail-epmap<br><br>avail-epmap<br>
zymed-zpp                2133/tcp  # zymed-zpp<br><br>zymed-zpp<br>
zymed-zpp                2133/udp  # zymed-zpp<br><br>zymed-zpp<br>
avenue                   2134/tcp  # avenue<br><br>avenue<br>
avenue                   2134/udp  # avenue<br><br>avenue<br>
iwserver                 2166/tcp  # iwserver<br><br>iwserver<br>
iwserver                 2166/udp  # iwserver<br><br>iwserver<br>
wnn4_Cn                  22289/tcp  # wnn4_Cn<br><br>wnn6 (chinese input), wnn4 (chinese input)<br>
                         /udp  # 
wnn4_Kr                  22305/tcp  # wnn4_Kr<br><br>wnn4 (korean input), wnn6 (korean input)<br>
                         /udp  # 
wnn4_Tw                  22321/tcp  # wnn4_Tw<br><br>wnn4 (taiwanse input), wnn6 (taiwanse input)<br>
                         /udp  # 
sd-request               2384/tcp  # sd-request<br><br>sd-request<br>
sd-request               2384/udp  # sd-request<br><br>sd-request<br>
priv-mail                24/tcp  # priv-mail<br><br>any private mail system<br>
priv-mail                24/udp  # priv-mail<br><br>any private mail system<br>
cp-svn                   18264/tcp  # Check Point SVN foundation (HTTP)
                         /udp  # 
                         /tcp  # 
hunt                     26740/udp  # hunt<br><br>multi-player/multi-host maze-wars, hunt(6)<br>
flex-lm                  27001/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27002/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27003/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27004/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27005/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27006/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27007/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27008/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
flex-lm                  27009/tcp  # flex-lm<br><br>flex lm (1-10)<br>
                         /udp  # 
                         /tcp  # 
Trinoo_Bcast             27444/udp  # Trinoo_Bcast<br><br>trinoo distributed attack tool master -> bcast daemon communication<br>
Trinoo_Master            27665/tcp  # Trinoo_Master<br><br>trinoo distributed attack tool master server control port<br>
                         /udp  # 
gtp-user                 285/tcp  # gtp-user<br><br>gtp-user plane (3gpp)<br>
gtp-user                 285/udp  # gtp-user<br><br>gtp-user plane (3gpp)<br>
fxp-1                    286/tcp  # fxp-1<br><br>fxp-1<br>
fxp-1                    286/udp  # fxp-1<br><br>fxp-1<br>
k-block                  287/tcp  # k-block<br><br>k-block<br>
k-block                  287/udp  # k-block<br><br>k-block<br>
dfoxserver               2960/tcp  # dfoxserver<br><br>dfoxserver<br>
dfoxserver               2960/udp  # dfoxserver<br><br>dfoxserver<br>
distrib-net-proxy        3064/tcp  # distrib-net-proxy<br><br>stupid closed source distributed.net project proxy port<br>
                         /udp  # 
lv-frontpanel            3079/tcp  # lv-frontpanel<br><br>lv front panel<br>
lv-frontpanel            3079/udp  # lv-frontpanel<br><br>lv front panel<br>
itm-mccs                 3084/tcp  # itm-mccs<br><br>itm-mccs<br>
itm-mccs                 3084/udp  # itm-mccs<br><br>itm-mccs<br>
pcihreq                  3085/tcp  # pcihreq<br><br>pcihreq<br>
pcihreq                  3085/udp  # pcihreq<br><br>pcihreq<br>
                         /tcp  # 
jdl-dbkitchen            3086/udp  # jdl-dbkitchen<br><br>jdl-dbkitchen<br>
ca-licmgr                10203/tcp  # Computer Associates License Manager
                         /udp  # 
                         /tcp  # 
Trinoo_Register          31335/udp  # Trinoo_Register<br><br>trinoo distributed attack tool bcast daemon registration port<br>
                         /tcp  # 
sometimes-rpc6           32771/udp  # sometimes-rpc6<br><br>sometimes an rpc port on my solaris box (rusersd)<br>
                         /tcp  # 
sometimes-rpc8           32772/udp  # sometimes-rpc8<br><br>sometimes an rpc port on my solaris box (status)<br>
                         /tcp  # 
sometimes-rpc10          32773/udp  # sometimes-rpc10<br><br>sometimes an rpc port on my solaris box (rquotad)<br>
                         /tcp  # 
sometimes-rpc12          32774/udp  # sometimes-rpc12<br><br>sometimes an rpc port on my solaris box (rusersd)<br>
                         /tcp  # 
sometimes-rpc14          32775/udp  # sometimes-rpc14<br><br>sometimes an rpc port on my solaris box (status)<br>
                         /tcp  # 
sometimes-rpc16          32776/udp  # sometimes-rpc16<br><br>sometimes an rpc port on my solaris box (sprayd)<br>
                         /tcp  # 
sometimes-rpc18          32777/udp  # sometimes-rpc18<br><br>sometimes an rpc port on my solaris box (walld)<br>
                         /tcp  # 
sometimes-rpc20          32778/udp  # sometimes-rpc20<br><br>sometimes an rpc port on my solaris box (rstatd)<br>
                         /tcp  # 
sometimes-rpc22          32779/udp  # sometimes-rpc22<br><br>sometimes an rpc port on my solaris box<br>
                         /tcp  # 
sometimes-rpc24          32780/udp  # sometimes-rpc24<br><br>sometimes an rpc port on my solaris box<br>
watcomdebug              3563/tcp  # watcomdebug<br><br>watcom debug<br>
watcomdebug              3563/udp  # watcomdebug<br><br>watcom debug<br>
harlequinorb             3672/tcp  # harlequinorb<br><br>harlequinorb<br>
harlequinorb             3672/udp  # harlequinorb<br><br>harlequinorb<br>
cscp                     40841/tcp  # cscp<br><br>cscp<br>
cscp                     40841/udp  # cscp<br><br>cscp<br>
vrml-multi-use           4201/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4202/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4203/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4204/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4205/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4206/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4207/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4208/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4209/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4210/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4211/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4212/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4213/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4214/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4215/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4216/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4217/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4218/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4219/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4220/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4221/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4222/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4223/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4224/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4225/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4226/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4227/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4228/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4229/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4230/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4231/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4232/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4233/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4234/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4235/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4236/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4237/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4238/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4239/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4240/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4241/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4242/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4243/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4244/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4245/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4246/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4247/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4248/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4249/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4250/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4251/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4252/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4253/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4254/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4255/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4256/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4257/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4258/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4259/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4260/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4261/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4262/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4263/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4264/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4265/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4266/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4267/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4268/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4269/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4270/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4271/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4272/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4273/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4274/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4275/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4276/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4277/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4278/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4279/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4280/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4281/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4282/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4283/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4284/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4285/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4286/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4287/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4288/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4289/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4290/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4291/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4292/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4293/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4294/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4295/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4296/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4297/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4298/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
vrml-multi-use           4299/tcp  # vrml-multi-use<br><br>vrml multi user systems<br>
                         /udp  # 
reachout                 43118/tcp  # reachout<br><br><br>
                         /udp  # 
msql                     4333/tcp  # msql<br><br>mini-sql server<br>
                         /udp  # 
fax                      4557/tcp  # fax<br><br>flexfax fax transmission service, fax transmission service<br>
                         /udp  # 
hylafax                  4559/tcp  # hylafax<br><br>hylafax client-server protocol<br>
                         /udp  # 
ssr-servermgr            45966/tcp  # ssr-servermgr<br><br>ssrservermgr<br>
ssr-servermgr            45966/udp  # ssr-servermgr<br><br>ssrservermgr<br>
sgi-dgl                  5232/tcp  # sgi-dgl<br><br>sgi distributed graphics<br>
                         /udp  # 
postgres                 5432/tcp  # postgres<br><br>postgres database server<br>
                         /udp  # 
netops-broker            5465/tcp  # netops-broker<br><br>netops-broker<br>
netops-broker            5465/udp  # netops-broker<br><br>netops-broker<br>
canna                    5680/tcp  # canna<br><br>canna (japanese input), kana->kanji server<br>
                         /udp  # 
unieng                   5730/tcp  # unieng<br><br>netscape suiteware<br>
                         /udp  # 
unisnc                   5731/tcp  # unisnc<br><br>netscape suiteware<br>
                         /udp  # 
unidas                   5732/tcp  # unidas<br><br>netscape suiteware<br>
                         /udp  # 
vnc                      5800/tcp  # vnc<br><br><br>
                         /udp  # 
vnc                      5801/tcp  # vnc<br><br><br>
                         /udp  # 
vnc                      5900/tcp  # vnc<br><br>virtual network computer, orl virtual network client<br>
                         /udp  # 
vnc-1                    5901/tcp  # vnc-1<br><br>virtual network computer display :1<br>
                         /udp  # 
vnc-2                    5902/tcp  # vnc-2<br><br>virtual network computer display :2<br>
                         /udp  # 
ncd-pref-tcp             5977/tcp  # ncd-pref-tcp<br><br>ncd preferences tcp port<br>
                         /udp  # 
ncd-diag-tcp             5978/tcp  # ncd-diag-tcp<br><br>ncd diagnostic tcp port<br>
                         /udp  # 
ncd-conf-tcp             5979/tcp  # ncd-conf-tcp<br><br>ncd configuration tcp port<br>
                         /udp  # 
ncd-pref                 5997/tcp  # ncd-pref<br><br>ncd preferences telnet port<br>
                         /udp  # 
ncd-diag                 5998/tcp  # ncd-diag<br><br>ncd diagnostic telnet port<br>
                         /udp  # 
cvsup                    5999/tcp  # cvsup<br><br>cvsup file transfer/john polstra/freebsd, ncd configuration telnet port<br>
                         /udp  # 
                         /tcp  # 
x11                      6001/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6002/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6003/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6004/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6005/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6006/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6007/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6008/udp  # x11<br><br>x window system<br>
                         /tcp  # 
x11                      6009/udp  # x11<br><br>x window system<br>
x11                      6010/tcp  # x11<br><br>x window system<br>
x11                      6010/udp  # x11<br><br>x window system<br>
x11                      6011/tcp  # x11<br><br>x window system<br>
x11                      6011/udp  # x11<br><br>x window system<br>
x11                      6012/tcp  # x11<br><br>x window system<br>
x11                      6012/udp  # x11<br><br>x window system<br>
x11                      6013/tcp  # x11<br><br>x window system<br>
x11                      6013/udp  # x11<br><br>x window system<br>
x11                      6014/tcp  # x11<br><br>x window system<br>
x11                      6014/udp  # x11<br><br>x window system<br>
x11                      6015/tcp  # x11<br><br>x window system<br>
x11                      6015/udp  # x11<br><br>x window system<br>
x11                      6016/tcp  # x11<br><br>x window system<br>
x11                      6016/udp  # x11<br><br>x window system<br>
x11                      6017/tcp  # x11<br><br>x window system<br>
x11                      6017/udp  # x11<br><br>x window system<br>
x11                      6018/tcp  # x11<br><br>x window system<br>
x11                      6018/udp  # x11<br><br>x window system<br>
x11                      6019/tcp  # x11<br><br>x window system<br>
x11                      6019/udp  # x11<br><br>x window system<br>
x11                      6020/tcp  # x11<br><br>x window system<br>
x11                      6020/udp  # x11<br><br>x window system<br>
x11                      6021/tcp  # x11<br><br>x window system<br>
x11                      6021/udp  # x11<br><br>x window system<br>
x11                      6022/tcp  # x11<br><br>x window system<br>
x11                      6022/udp  # x11<br><br>x window system<br>
x11                      6023/tcp  # x11<br><br>x window system<br>
x11                      6023/udp  # x11<br><br>x window system<br>
x11                      6024/tcp  # x11<br><br>x window system<br>
x11                      6024/udp  # x11<br><br>x window system<br>
x11                      6025/tcp  # x11<br><br>x window system<br>
x11                      6025/udp  # x11<br><br>x window system<br>
x11                      6026/tcp  # x11<br><br>x window system<br>
x11                      6026/udp  # x11<br><br>x window system<br>
x11                      6027/tcp  # x11<br><br>x window system<br>
x11                      6027/udp  # x11<br><br>x window system<br>
x11                      6028/tcp  # x11<br><br>x window system<br>
x11                      6028/udp  # x11<br><br>x window system<br>
x11                      6029/tcp  # x11<br><br>x window system<br>
x11                      6029/udp  # x11<br><br>x window system<br>
x11                      6030/tcp  # x11<br><br>x window system<br>
x11                      6030/udp  # x11<br><br>x window system<br>
x11                      6031/tcp  # x11<br><br>x window system<br>
x11                      6031/udp  # x11<br><br>x window system<br>
x11                      6032/tcp  # x11<br><br>x window system<br>
x11                      6032/udp  # x11<br><br>x window system<br>
x11                      6033/tcp  # x11<br><br>x window system<br>
x11                      6033/udp  # x11<br><br>x window system<br>
x11                      6034/tcp  # x11<br><br>x window system<br>
x11                      6034/udp  # x11<br><br>x window system<br>
x11                      6035/tcp  # x11<br><br>x window system<br>
x11                      6035/udp  # x11<br><br>x window system<br>
x11                      6036/tcp  # x11<br><br>x window system<br>
x11                      6036/udp  # x11<br><br>x window system<br>
x11                      6037/tcp  # x11<br><br>x window system<br>
x11                      6037/udp  # x11<br><br>x window system<br>
x11                      6038/tcp  # x11<br><br>x window system<br>
x11                      6038/udp  # x11<br><br>x window system<br>
x11                      6039/tcp  # x11<br><br>x window system<br>
x11                      6039/udp  # x11<br><br>x window system<br>
x11                      6040/tcp  # x11<br><br>x window system<br>
x11                      6040/udp  # x11<br><br>x window system<br>
x11                      6041/tcp  # x11<br><br>x window system<br>
x11                      6041/udp  # x11<br><br>x window system<br>
x11                      6042/tcp  # x11<br><br>x window system<br>
x11                      6042/udp  # x11<br><br>x window system<br>
x11                      6043/tcp  # x11<br><br>x window system<br>
x11                      6043/udp  # x11<br><br>x window system<br>
x11                      6044/tcp  # x11<br><br>x window system<br>
x11                      6044/udp  # x11<br><br>x window system<br>
x11                      6045/tcp  # x11<br><br>x window system<br>
x11                      6045/udp  # x11<br><br>x window system<br>
x11                      6046/tcp  # x11<br><br>x window system<br>
x11                      6046/udp  # x11<br><br>x window system<br>
x11                      6047/tcp  # x11<br><br>x window system<br>
x11                      6047/udp  # x11<br><br>x window system<br>
x11                      6048/tcp  # x11<br><br>x window system<br>
x11                      6048/udp  # x11<br><br>x window system<br>
x11                      6049/tcp  # x11<br><br>x window system<br>
x11                      6049/udp  # x11<br><br>x window system<br>
x11                      6050/tcp  # x11<br><br>x window system<br>
x11                      6050/udp  # x11<br><br>x window system<br>
x11/AVG-Server           6051/tcp  # x11<br><br>x window system<br>, AVG anti-virus client connection to DataCenter
x11                      6051/udp  # x11<br><br>x window system<br>
x11                      6052/tcp  # x11<br><br>x window system<br>
x11                      6052/udp  # x11<br><br>x window system<br>
x11                      6053/tcp  # x11<br><br>x window system<br>
x11                      6053/udp  # x11<br><br>x window system<br>
x11                      6054/tcp  # x11<br><br>x window system<br>
x11                      6054/udp  # x11<br><br>x window system<br>
x11                      6055/tcp  # x11<br><br>x window system<br>
x11                      6055/udp  # x11<br><br>x window system<br>
x11                      6056/tcp  # x11<br><br>x window system<br>
x11                      6056/udp  # x11<br><br>x window system<br>
x11                      6057/tcp  # x11<br><br>x window system<br>
x11                      6057/udp  # x11<br><br>x window system<br>
x11                      6058/tcp  # x11<br><br>x window system<br>
x11                      6058/udp  # x11<br><br>x window system<br>
x11                      6059/tcp  # x11<br><br>x window system<br>
x11                      6059/udp  # x11<br><br>x window system<br>
x11                      6060/tcp  # x11<br><br>x window system<br>
x11                      6060/udp  # x11<br><br>x window system<br>
x11                      6061/tcp  # x11<br><br>x window system<br>
x11                      6061/udp  # x11<br><br>x window system<br>
x11                      6062/tcp  # x11<br><br>x window system<br>
x11                      6062/udp  # x11<br><br>x window system<br>
x11                      6063/tcp  # x11<br><br>x window system<br>
x11                      6063/udp  # x11<br><br>x window system<br>
ndl-ahp-svc              6064/tcp  # ndl-ahp-svc<br><br>ndl-ahp-svc<br>
ndl-ahp-svc              6064/udp  # ndl-ahp-svc<br><br>ndl-ahp-svc<br>
winpharaoh               6065/tcp  # winpharaoh<br><br>winpharaoh<br>
winpharaoh               6065/udp  # winpharaoh<br><br>winpharaoh<br>
ewctsp                   6066/tcp  # ewctsp<br><br>ewctsp<br>
ewctsp                   6066/udp  # ewctsp<br><br>ewctsp<br>
srb                      6067/tcp  # srb<br><br>srb<br>
srb                      6067/udp  # srb<br><br>srb<br>
gsmp                     6068/tcp  # gsmp<br><br>gsmp<br>
gsmp                     6068/udp  # gsmp<br><br>gsmp<br>
trip                     6069/tcp  # trip<br><br>trip<br>
trip                     6069/udp  # trip<br><br>trip<br>
messageasap              6070/tcp  # messageasap<br><br>messageasap<br>
messageasap              6070/udp  # messageasap<br><br>messageasap<br>
ssdtp                    6071/tcp  # ssdtp<br><br>ssdtp<br>
ssdtp                    6071/udp  # ssdtp<br><br>ssdtp<br>
                         /tcp  # 
diagmose-proc            6072/udp  # diagmose-proc<br><br>diagnose-proc<br>
directplay8              6073/tcp  # directplay8<br><br>directplay8<br>
directplay8              6073/udp  # directplay8<br><br>directplay8<br>
synchronet-db            6100/tcp  # synchronet-db<br><br>synchronet-db<br>
synchronet-db            6100/udp  # synchronet-db<br><br>synchronet-db<br>
synchronet-rtc           6101/tcp  # synchronet-rtc<br><br>synchronet-rtc<br>
synchronet-rtc           6101/udp  # synchronet-rtc<br><br>synchronet-rtc<br>
synchronet-upd           6102/tcp  # synchronet-upd<br><br>synchronet-upd<br>
synchronet-upd           6102/udp  # synchronet-upd<br><br>synchronet-upd<br>
rets                     6103/tcp  # rets<br><br>rets<br>
rets                     6103/udp  # rets<br><br>rets<br>
dbdb                     6104/tcp  # dbdb<br><br>dbdb<br>
dbdb                     6104/udp  # dbdb<br><br>dbdb<br>
primaserver              6105/tcp  # primaserver<br><br>prima server<br>
primaserver              6105/udp  # primaserver<br><br>prima server<br>
mpsserver                6106/tcp  # mpsserver<br><br>mps server<br>
mpsserver                6106/udp  # mpsserver<br><br>mps server<br>
etc-control              6107/tcp  # etc-control<br><br>etc control<br>
etc-control              6107/udp  # etc-control<br><br>etc control<br>
sercomm-scadmin          6108/tcp  # sercomm-scadmin<br><br>sercomm-scadmin<br>
sercomm-scadmin          6108/udp  # sercomm-scadmin<br><br>sercomm-scadmin<br>
globecast-id             6109/tcp  # globecast-id<br><br>globecast-id<br>
globecast-id             6109/udp  # globecast-id<br><br>globecast-id<br>
gnutella/gnutella        6346/tcp  # gnutella<br><br>gnutella, the gnu napster<br>, Gnutella, Limewire, Morpheus, BearShare
gnutella                 6346/udp  # Gnutella, Limewire, Morpheus, BearShare
info-cachesvr            6403/tcp  # Info - Cache Server<BR>
                         /udp  # 
reserved1                6407/tcp  # reserved1<br><br><br>
                         /udp  # 
reserved2                6408/tcp  # reserved2<br><br><br>
                         /udp  # 
reserved3                6409/tcp  # reserved3<br><br><br>
                         /udp  # 
reserved4                6410/tcp  # reserved4<br><br><br>
                         /udp  # 
dhcp-failover            647/tcp  # dhcp-failover<br><br>dhcp failover<br>
dhcp-failover            647/udp  # dhcp-failover<br><br>dhcp failover<br>
                         /tcp  # 
ircu                     6666/udp  # ircu<br><br>ircu<br>
ircu                     6669/tcp  # ircu<br><br>ircu<br>
ircu                     6669/udp  # ircu<br><br>ircu<br>
swx                      7301/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7302/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7303/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7304/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7305/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7306/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7307/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7308/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7309/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7310/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7311/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7312/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7313/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7314/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7315/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7316/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7317/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7318/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7319/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7320/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7321/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7322/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7323/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7324/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7325/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7326/tcp  # swx<br><br>the swiss exchange, internet citizen's band<br>
                         /udp  # 
swx                      7327/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7328/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7329/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7330/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7331/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7332/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7333/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7334/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7335/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7336/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7337/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7338/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7339/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7340/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7341/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7342/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7343/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7344/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7345/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7346/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7347/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7348/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7349/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7350/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7351/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7352/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7353/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7354/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7355/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7356/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7357/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7358/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7359/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7360/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7361/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7362/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7363/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7364/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7365/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7366/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7367/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7368/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7369/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
                         /tcp  # 
sometimes-rpc2           737/udp  # sometimes-rpc2<br><br>rusersd on my openbsd box<br>
swx                      7370/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7371/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7372/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7373/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7374/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7375/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7376/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7377/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7378/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7379/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7380/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7381/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7382/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7383/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7384/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7385/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7386/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7387/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7388/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7389/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
swx                      7390/tcp  # swx<br><br>the swiss exchange<br>
                         /udp  # 
netcp                    740/tcp  # netcp<br><br>netscout control protocol<br>
netcp                    740/udp  # netcp<br><br>netscout control protocol<br>
priv-dial                75/tcp  # priv-dial<br><br>any private dial out service<br>
priv-dial                75/udp  # priv-dial<br><br>any private dial out service<br>
                         /tcp  # 
cucme-3                  7650/udp  # cucme-3<br><br>cucme live video/audio server<br>
                         /tcp  # 
cucme-4                  7651/udp  # cucme-4<br><br>cucme live video/audio server<br>
minivend                 7786/tcp  # minivend<br><br>minivend<br>
minivend                 7786/udp  # minivend<br><br>minivend<br>
hp-collector             781/tcp  # hp-collector<br><br>hp performance data collector<br>
hp-collector             781/udp  # hp-collector<br><br>hp performance data collector<br>
hp-managed-node          782/tcp  # hp-managed-node<br><br>hp performance data managed node<br>
hp-managed-node          782/udp  # hp-managed-node<br><br>hp performance data managed node<br>
hp-alarm-mgr             783/tcp  # hp-alarm-mgr<br><br>hp performance data alarm manager<br>
hp-alarm-mgr             783/udp  # hp-alarm-mgr<br><br>hp performance data alarm manager<br>
controlit                799/tcp  # controlit<br><br><br>
                         /udp  # 
supfilesrv               871/tcp  # supfilesrv<br><br>sup server, for sup<br>
                         /udp  # 
openqueue                8764/tcp  # openqueue<br><br>openqueue<br>
openqueue                8764/udp  # openqueue<br><br>openqueue<br>
jetdirect                9100/tcp  # jetdirect<br><br>hp jetdirect card<br>
                         /udp  # 
sctp-tunneling           9899/tcp  # sctp-tunneling<br><br>sctp tunneling<br>
sctp-tunneling           9899/udp  # sctp-tunneling<br><br>sctp tunneling<br>
apcpcpluswin1            9950/tcp  # apcpcpluswin1<br><br>apcpcpluswin1<br>
apcpcpluswin1            9950/udp  # apcpcpluswin1<br><br>apcpcpluswin1<br>
apcpcpluswin2            9951/tcp  # apcpcpluswin2<br><br>apcpcpluswin2<br>
apcpcpluswin2            9951/udp  # apcpcpluswin2<br><br>apcpcpluswin2<br>
apcpcpluswin3            9952/tcp  # apcpcpluswin3<br><br>apcpcpluswin3<br>
apcpcpluswin3            9952/udp  # apcpcpluswin3<br><br>apcpcpluswin3<br>
palace                   9993/tcp  # palace<br><br>palace<br>
palace                   9993/udp  # palace<br><br>palace<br>
palace                   9994/tcp  # palace<br><br>palace<br>
palace                   9994/udp  # palace<br><br>palace<br>
palace                   9995/tcp  # palace<br><br>palace<br>
palace                   9995/udp  # palace<br><br>palace<br>
palace                   9996/tcp  # palace<br><br>palace<br>
palace                   9996/udp  # palace<br><br>palace<br>
palace                   9997/tcp  # palace<br><br>palace<br>
palace                   9997/udp  # palace<br><br>palace<br>
waste                    1337/tcp  # p2p file sharing: http://www.sourceforget.net/projects/waste/
                         /udp  # 
power-broker/pbmaster     24345/tcp  # Symark Power-Broker, PowerBroker Master Daemon
                         /udp  # 
power-broker/pblocald     24346/tcp  # Symark Power-Broker, PowerBroker local daemon
                         /udp  # 
power-broker             24347/tcp  # Symark Power-Broker
                         /udp  # 
Google-desktop           4664/tcp  # Google Desktop search agent port, HTTP. Localhost only.
                         /udp  # 
tftpn                    5452/tcp  # Sequoia failover xport (Nokia)
                         /udp  # 
DB2                      50000/tcp  # IBM DB2
                         /udp  # 
webmail2                 3511/tcp  # 
                         /udp  # 
sadmin                   698/tcp  # Solaris sadmin
                         /udp  # 
ca-licmgr                10204/tcp  # Computer Associates License Manager
                         /udp  # 
hddtemp                  7634/tcp  # 
                         /udp  # 
bf2/battlefield2         16567/tcp  # Battlefield II, 
                         /udp  # 
LCDproc                  13666/tcp  # 
                         /udp  # 
famatech -admin          4899/tcp  # famatech remote administrator 
                         /udp  # 
limewire                 6347/tcp  # Limewire, Morpheus
limewire                 6347/udp  # Limewire, Morpheus
Emule-Edonkey            4662/tcp  # P2P
                         /udp  # 
BitTorrent               6881/tcp  # P2P
BitTorrent               6881/udp  # P2P
BitTorrent               6882/tcp  # P2P
BitTorrent               6882/udp  # P2P
BitTorrent               6883/tcp  # P2P
BitTorrent               6883/udp  # P2P
BitTorrent               6884/tcp  # P2P
BitTorrent               6884/udp  # P2P
BitTorrent               6885/tcp  # P2P
BitTorrent               6885/udp  # P2P
BitTorrent               6886/tcp  # P2P
BitTorrent               6886/udp  # P2P
BitTorrent               6887/tcp  # P2P
BitTorrent               6887/udp  # P2P
BitTorrent               6888/tcp  # P2P
BitTorrent               6888/udp  # P2P
BitTorrent               6889/tcp  # P2P
BitTorrent               6889/udp  # P2P
                         /tcp  # 
winmx                    6257/udp  # WinMx, Napster
AVG-Server               4156/tcp  # AVG TCP Server connection 
                         /udp  # 
AVG-Agent                6150/tcp  # AVG Agent port (for remote installation)
                         /udp  # 
Interwoven-CMS           3434/tcp  # Interwoven Content Management System
                         /udp  # 
db2                      6789/tcp  # IBM DB2
                         /udp  # 
OperaBT                  18768/tcp  # Opera browser's Bittorrent client
                         /udp  # 
DMRC                     6129/tcp  # DMRC Client Agent Service, http://www.dameware.com/
                         /udp  # 
MikroTik Router OS Winbox Configuration Interface     8291/tcp  # 
                         /udp  # 
MikroTik Router OS API Custom Management Inferface     8278/tcp  # 
                         /udp  # 
VxWorks-debug            17185/tcp  # 
                         /udp  # 
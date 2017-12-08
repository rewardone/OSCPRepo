#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-

"""
linux-exploit-checker.py - Linux Local Privilege Escalation Exploit Checker
Copyright (C) 2010-2011  Bernardo Damele A. G.
web: http://bernardodamele.blogspot.com/
email: bernardo.damele@gmail.com

This script is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

Changelog:

2010-07-19 linux-exploit-check.py v1.0 BDA

* Initial release

2010-07-20 linux-exploit-check.py v1.1 MRL

* Takes kernel version as optional command line argument
* Reformatted output to avoid line wrapping
* Added version number
* Removed DOS line endings

2010-07-21 linux-exploit-check.py v1.2 BDA

* Fixed string comparison
* Minor bug fix
* Layout adjustments

2010-11-08 linux-exploit-check.py v1.3 BDA

* Added reference to three recent exploits

2011-09-14 linux-exploit-check.py v1.4 BDA

* Added reference to four recent exploits
"""

import os
import re
import sys

exploitdb_url = "http://www.exploit-db.com/exploits"
enlightenment_url = "http://www.grsecurity.net/~spender/enlightenment.tgz"
version = "1.4"
scriptname = os.path.basename(sys.argv[0])

def fix_version(version):
    split_version = version.split(".")

    if len(split_version) >= 3 and len(split_version[2]) == 1:
        split_version[2] = "0%s" % split_version[2]
        # version = ".".join(v for v in split_version)
        version = ".".join(split_version)

    return version

def main():
    print "%s v%s\n" % (scriptname, version)

    if len(sys.argv) == 2:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help':
            print "Usage: %s [kernel-version]" % scriptname
            sys.exit(0)
        else:
            kernel_version_string = sys.argv[1]
            print "[*] Given kernel version: %s" % kernel_version_string
    else:
        kernel_version_string = os.popen('uname -r').read().strip()
        print "[*] Automatically detected local kernel version: %s" % kernel_version_string

    kernel_parts = kernel_version_string.split("-")
    kernel_version = fix_version(kernel_parts[0])
    found_exploit = False
    exploits = {
                 "do_brk": { "CVE": "2003-0961", "versions": ("2.4.0-2.4.22",), "exploits": (131,) },
                 "mremap missing do_munmap": { "CVE": "2004-0077", "versions": ("2.2.0-2.2.25", "2.4.0-2.4.24", "2.6.0-2.6.2"), "exploits": (160,) },
                 "binfmt_elf Executable File Read": { "CVE": "2004-1073", "versions": ("2.4.0-2.4.27", "2.6.0-2.6.8"), "exploits": (624,) },
                 "uselib()": { "CVE": "2004-1235", "versions": ("2.4.0-2.4.29rc2", "2.6.0-2.6.10rc2"), "exploits": (895,) },
                 "bluez": { "CVE": "2005-1294", "versions": ("2.6.0-2.6.11.5",), "exploits": (4756, 926) },
                 "prctl()": { "CVE": "2006-2451", "versions": ("2.6.13-2.6.17.4",), "exploits": (2031, 2006, 2011, 2005, 2004) }, 
                 "proc": { "CVE": "2006-3626", "versions": ("2.6.0-2.6.17.4",), "exploits": (2013,) },
                 "system call emulation": { "CVE": "2007-4573", "versions": ("2.4.0-2.4.30", "2.6.0-2.6.22.7",), "exploits": (4460,) },
                 "vmsplice": { "CVE": "2008-0009", "versions": ("2.6.17-2.6.24.1",), "exploits": (5092, 5093) },
                 "ftruncate()/open()": { "CVE": "2008-4210", "versions": ("2.6.0-2.6.22",), "exploits": (6851,) },
                 "eCryptfs (Paokara)": { "CVE": "2009-0269", "versions": ("2.6.19-2.6.31.1",), "exploits": (enlightenment_url,) },
                 "set_selection() UTF-8 Off By One": { "CVE": "2009-1046", "versions": ("2.6.0-2.6.28.3",), "exploits": (9083,) },
                 "UDEV < 141": { "CVE": "2009-1185", "versions": ("2.6.25-2.6.30",), "exploits": (8478, 8572) },
                 "exit_notify()": { "CVE": "2009-1337", "versions": ("2.6.0-2.6.29",), "exploits": (8369,) },
                 "ptrace_attach() Local Root Race Condition": { "CVE": "2009-1527", "versions": ("2.6.29",), "exploits": (8678, 8673) },
                 "sock_sendpage() (Wunderbar Emporium)": { "CVE": "2009-2692", "versions": ("2.6.0-2.6.31rc3", "2.4.0-2.4.37.1"), "exploits": (9641, 9545, 9479, 9436, 9435, enlightenment_url) },
                 "udp_sendmsg() (The Rebel)": { "CVE": "2009-2698", "versions": ("2.6.0-2.6.9.2",), "exploits": (9575, 9574, enlightenment_url) },
                 "(32bit) ip_append_data() ring0": { "CVE": "2009-2698", "versions": ("2.6.0-2.6.9",), "exploits": (9542,) },
                 "perf_counter_open() (Powerglove and Ingo m0wnar)": { "CVE": "2009-3234", "versions": ("2.6.31",), "exploits": (enlightenment_url,) },
                 "pipe.c (MooseCox)": { "CVE": "2009-3547", "versions": ("2.6.0-2.6.32rc5", "2.4.0-2.4.37"), "exploits": (10018, enlightenment_url) },
                 "CPL 0": { "CVE": "2010-0298", "versions": ("2.6.0-2.6.11",), "exploits": (1397,) },
                 "ReiserFS xattr": { "CVE": "2010-1146", "versions": ("2.6.0-2.6.34rc3",), "exploits": (12130,) },
                 "Unknown": { "CVE": None, "versions": ("2.6.18-2.6.20",), "exploits": (10613,) },
                 "SELinux/RHEL5 (Cheddar Bay)": { "CVE": None, "versions": ("2.6.9-2.6.30",), "exploits": (9208, 9191, enlightenment_url) },
                 "compat": { "CVE": "2010-3301", "versions": ("2.6.27-2.6.36rc4",), "exploits": (15023, 15024) },
                 "BCM": { "CVE": "2010-2959", "versions": ("2.6.0-2.6.36rc1",), "exploits": (14814,) },
                 "RDS protocol": { "CVE": "2010-3904", "versions": ("2.6.0-2.6.36rc8",), "exploits": (15285,) },
                 "put_user() - full-nelson": { "CVE": "2010-4258", "versions": ("2.6.0-2.6.37",), "exploits": (15704,) },
                 "sock_no_sendpage() - full-nelson": { "CVE": "2010-3849", "versions": ("2.6.0-2.6.37",), "exploits": (15704,) },
                 "ACPI custom_method": { "CVE": "2010-4347", "versions": ("2.6.0-2.6.37rc2",), "exploits": (15774,) },
                 "CAP_SYS_ADMIN": { "CVE": "2010-4347", "versions": ("2.6.34-2.6.37",), "exploits": (15916, 15944) },
                 "econet_sendmsg() - half-nelson": { "CVE": "2010-3848", "versions": ("2.6.0-2.6.36.2",), "exploits": (17787,) },
                 "ec_dev_ioctl() - half-nelson": { "CVE": "2010-3850", "versions": ("2.6.0-2.6.36.2",), "exploits": (17787, 15704) },
                 "ipc - half-nelson": { "CVE": "2010-4073", "versions": ("2.6.0-2.6.37rc1",), "exploits": (17787,) },
               }

    print "[+] Possible exploits:"

    for name, data in exploits.items():
        versions = data["versions"] 

        for version_tree in versions:
            if "-" in version_tree:
                min_version, max_version = version_tree.split("-")
            else:
                min_version, max_version = version_tree, version_tree

            if kernel_version >= fix_version(min_version) and kernel_version <= fix_version(max_version):
                cve = data["CVE"]
                exploits = data["exploits"]
                found_exploit = True
                exploits_str = ""

                for expl in exploits:
                    if isinstance(expl, int):
                        exploits_str += "        %s/%d\n" % (exploitdb_url, expl)
                    else:
                        exploits_str += "        %s" % expl 

                print """
[*] Linux Kernel %s Local Root Exploit
    CVE: CVE-%s\n    Affects kernels: %s-%s
    Exploits:\n%s""" % (name, cve, min_version, max_version, exploits_str)

    if found_exploit:
        print

        if len(kernel_parts) > 1:
            print "WARNING: %s appears to be a modified version of kernel %s." % (kernel_version_string, kernel_version)
            print "These exploits can *possibly* get you to uid=0, but this script does *not* consider patched or backported kernel version\n"

if __name__ == "__main__":
    main()

Shell script to check for simple privilege escalation vectors on Unix systems

Unix-privesc-checker is a script that runs on Unix systems (tested on Solaris 9, HPUX 11, Various Linuxes, FreeBSD 6.2).  It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).  

It is written as a single shell script so it can be easily uploaded and run (as opposed to un-tarred, compiled and installed).  It can run either as a normal user or as root (obviously it does a better job when running as root because it can read more files).

Also see: http://pentestmonkey.net/tools/unix-privesc-check/

This project contains two branches that are actively maintained:
* Branch "1_x", that contains a single shell script, "unix-privesc-check" that needs to be uploaded and run on the target system.  The script runs fairly quickly.  The code, while a bit ugly is stable and mature.  https://github.com/pentestmonkey/unix-privesc-check/tree/1_x
* Branch "master", that contains a script "upc.sh" and some subdirectories that need to be uploaded and run on the target system.  The script is generally slower, but more thorough in some ways.  The code is much nicer, though somewhat experimental.  https://github.com/pentestmonkey/unix-privesc-check/tree/master

If in doubt, try both.

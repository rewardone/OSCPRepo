@echo Running Intrusion Detection Script v1.0
@echo ***********************************************
@echo Sans.org Whitepaper: 
@echo simple-windows-batch-scripting-intrusion-discovery-33193
@echo ***********************************************
@echo Requires tools: dumpsec, nbtstat, fport, reg, at
@echo schtasks, dumpel, chkntfs, rootkitrevealer, net use

rem **** version, services and processes********************
ver > ver.txt
dumpsec /rpt=services /saveas=csv /outfile=c:\ local-services.csv
Tasklist /v >Tasklist.txt
Net Start >networkservices.txt
Net view \\127.0.0.1 >openshares.txt
Net Session >sessions.txt
nbtstat -s >nbtstat1.txt
nbtstat -S >nbtstat2.txt
netstat -na >netstat.txt
fport > fports.txt

rem **** shares and users ********************************
dumpsec /rpt=shares /saveas=csv /outfile=c:\shares.csv
dumpsec /rpt=users /saveas=csv /outfile=c:\lsusers.csv /showaudit

rem **** registry ***************************************
Reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run c:\ Run.reg
Reg export HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce c:\ RunOnce.reg
Reg export HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx c:\ RunOnceEx.reg
Reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run c:\ UserRun.reg
Reg export HKCU\Software\Microsoft\Windows\CurrentVersion\Run c:\ UserRunOnce.reg
Reg export HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx c:\
UserRunOnceEX.reg

rem **** scheduled tasks and event logs **********************
AT >c:\ scheduledATtasks.txt
Schtasks > c:\schtasks.txt
dumpel -f securitylog.txt -l security

rem **** file system and large files **************************
chkntfs c: > ntfs.txt
 ‘C:\> for /r c:\ %i in (*) do @echo %~zi, %i > files.csv’
 
rem **** rootkit detection *********************************
rootkitrevealer.exe -a rootkit.log

rem **** Copy extracted data files to the repository ************
net use z: \\%your file server and path%
copy *.txt z:\%your file server and path%
copy *.csv z:\%your file server and path%
copy *.reg z:\%your file server and path%
copy *.log z:\%your file server and path%

@echo *************************************************
@echo Script Complete!
# This is a python script to enumerate a local windows system for
# privilege escalation attempts.
# accesschk from SysInternals is required to be in the same root directory as this
# script in order for it to work.

# By sn0wfa11

import subprocess
import os.path
import os
import sys
import csv
import codecs
import argparse

raw = "IU93xy0Px.csv"
path_list = []
basic = "basic_info.txt"
network = "network_info.txt"
firewall = "firewall_info.txt"
tasks = "task_service_info.txt"
driver = "driver_info.txt"
service = "service_info.txt"
service_tmp1 = "service_tmp1.txt"
service_tmp2 = "service_tmp2.txt"
patches = "patch_info.txt"
fast_priv = "fast_priv.txt"
wmic_chk = "wmic_check.txt"
check = "dki98kxAI.bat"
 
def check_dependencies():
  if not os.path.isfile("accesschk.exe"):
    print "accesschk.exe from SysInternals must be in same folder as this script... Exiting."
    sys.exit(0)

def sys_call(arg, file):
  cal = subprocess.call(arg + ' >> ' + file, shell=True)
  
def echo_call(arg):
  cal = subprocess.call(arg, shell=True)
  
def sys_call_new(arg, file):
   cal = subprocess.call(arg + ' > ' + file, shell=True)
  
def blank_line(file):
  sys_call("echo.", file)
	
def file_header(file):
  cal = subprocess.call("echo Windows Local Enumeration by Sn0wFa11 > " + file, shell=True)
  sys_call("echo =====================================", file)
  blank_line(file)
  
def divider(file):
  sys_call("echo --------------------------------------------------------------------", file)

def section_heading(title, file):
  border = '+' * (len(title) + 4)
  sys_call("echo " + border, file)
  sys_call("echo + " + title + " +", file)
  sys_call("echo " + border, file)
  blank_line(file)

def part_heading(title, file):
  sys_call("echo " + title + ":", file)
 
def basic_enum():
  print "Runnng Windows Basic System Information Enumeration."
  file_header(basic)
  section_heading("Basic System Enumeration", basic)
  
  part_heading("System Info", basic)
  sys_call('systeminfo | findstr /B /C:"OS Name" /C:"OS Version"', basic)
  divider(basic)
  
  part_heading("Hostname", basic)
  sys_call('hostname', basic)
  divider(basic)  
  
  part_heading("Current User", basic)
  sys_call('echo %username%', basic)
  divider(basic)
  
  part_heading("Path", basic)
  sys_call('echo %path%', basic)
  divider(basic)
  
  part_heading("Users", basic)
  sys_call('net users', basic)
  
  part_heading("Administrators", basic)
  sys_call('net localgroup Administrators', basic)
  
  part_heading("RDP Users", basic)
  sys_call('net localgroup "Remote Desktop Users"', basic)
  divider(basic)
  
def network_enum():
  print "Running Local Network Enumeration."
  file_header(network)
  section_heading("Network Information", network)
  
  sys_call('ipconfig /all', network)
  divider(network)
  
  part_heading("Routes", network)
  sys_call('route print', network)
  divider(network)
  
  part_heading("Local Network", network)
  sys_call('arp -A', network)
  divider(network)

  sys_call('netstat -ano', network)
  divider(network)
  
def firewall_enum():
  print "Running Windows Firewall Enumeration."
  file_header(firewall)
  section_heading("Firewall Enumeration", firewall)
  
  sys_call('netsh firewall show state', firewall)
  divider(firewall)
  
  part_heading("Firewall Config", firewall)
  sys_call('netsh firewall show config', firewall)
  divider(firewall)
  
def tasks_sched_enum():
  print "Running Windows Tasks and Scheduled Process Enumeration."
  file_header(tasks)
  section_heading("Running Tasks and Services", tasks)
  
  part_heading("Tasks", tasks)
  sys_call('schtasks /query /fo LIST /v', tasks)
  divider(tasks)
  
  part_heading("Running Process", tasks)
  sys_call('tasklist /SVC', tasks)
  divider(tasks)
  
def service_enum():
  print "Windows Service Enumeration."
  file_header(service)
  section_heading("Service Executable Rights Enumeration", service)
  sys_call('echo SERVICE_CHANGE_CONFIG == Can reconfigure the service binary', service)
  sys_call('echo WRITE_DAC == Can reconfigure permissions to SERVICE_CHANGE_CONFIG', service)
  sys_call('echo WRITE_OWNER == Can become owner, reonfigure permissions', service)
  sys_call('echo GENERIC_WRITE == Inherits SERVICE_CHANGE_CONFIG', service)
  sys_call('echo GENERIC_ALL == Inherits SERVICE_CHANGE_CONFIG', service)
  divider(service)
  blank_line(service)
  part_heading("Services", service)
  sys_call('sc queryex type= service state= all | findstr /B /C:"SERVICE_NAME"', service_tmp1)
  lines = [line.rstrip('\n') for line in open(service_tmp1)]
  
  for line in lines:
    name = line.split(' ')[1]
    name = name.strip()
    command = 'sc qc ' + name + ' | findstr /C:"BINARY_PATH_NAME"'
    sys_call_new(command, service_tmp2)
    path_lines = [path_line.rstrip('\n') for path_line in open(service_tmp2)]
    for path_line in path_lines:
	  path_line = path_line.strip()
	  path = path_line.split(':')[1] + ':' + path_line.split(':')[2] 
	  path = path.strip()
	  path = path.split(' -')[0]
	  path = path.split(' /')[0]
	  path = path.strip()
	  path = quote_string(path)
	
    sys_call('sc qc ' + name, service)
    blank_line(service)
    sys_call('accesschk.exe -ucqv "' + name + '" /accepteula', service)
    blank_line(service)
    sys_call('accesschk.exe -q ' + path + ' /accepteula', service)
    divider(service)
	
  os.remove(service_tmp1)
  os.remove(service_tmp2)
  divider(service)

def quote_string(input):
  if input[0] != '"':
    input = '"' + input
  length = len(input)
  if input[length - 1] != '"':
    input = input + '"'
  return input
  
  print input[0]
  
def driver_enum():
  print "Running Windows Driver Enumeration."
  file_header(driver)
  section_heading("Driver Enumeration", driver)
  
  sys_call('DRIVERQUERY', driver)
  divider(driver)
  
def patch_enum():
  print "Running Windows Patch Enumeration."
  cal = subprocess.call('wmic qfe get Caption,Description,HotFixID,InstalledOn /format:table > ' + patches, shell=True)
  
def first_check():
  out = open(check, 'w')
  out.write('wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\\Windows\\\\" |findstr /i /v """\n')
  out.write('reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n')
  out.write('reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n')
  out.close()
    
  section_heading("Unquoted Service Paths and Always Installed Elevated", fast_priv)
  sys_call(check, fast_priv)
  divider(fast_priv)
  
  os.remove(check)
  
def second_check():
  section_heading("Unattended Install Check", fast_priv)
  sys_call('reg query HKLM\\System\\Setup!UnattendFile', fast_priv)
  file_list = ['unattend.xml', 'sysprep.xml', 'sysprep.inf', 'autounattend.xml']
  path_list = ['c:\\', 'c:\\Windows\\Panther\\', 'c:\\Windows\\Panther\\Unattend\\', 'c:\\Windows\\System32\\', 'c:\\Windows\\System32\\sysprep\\']
  for file in file_list:
    for path in path_list:
	  if os.path.isfile(path + file):
	    sys_call('echo Possible Unattended Install File: ', fast_priv)
	    sys_call('echo ' + path + file, fast_priv)

  blank_line(fast_priv)
  
def third_check():
  section_heading("Quck Accesschk Look - Won't Work >= Win XP SP2", fast_priv)
  sys_call('accesschk.exe -uwcqv "Authenticated Users" * /accepteula', fast_priv)
  blank_line(fast_priv)    
  
def fast_priv_enum():
  print "Running Fast Privilege Escalation Enumeration."
  file_header(fast_priv)
  first_check()
  second_check()
  third_check()

def wmic_check():
  print "Running WMIC Check"
  file_header(wmic_chk)
  servicelist = "wmic service get name,pathname /format:csv > " + raw
  cal = subprocess.call(servicelist, shell=True)

  if os.path.isfile(raw) == False:
    print "Something went wrong with service enumeration."
    return
  
  section_heading("Service Executable Rights Enumeration", wmic_chk)
  sys_call('echo SERVICE_CHANGE_CONFIG == Can reconfigure the service binary', wmic_chk)
  sys_call('echo WRITE_DAC == Can reconfigure permissions to SERVICE_CHANGE_CONFIG', wmic_chk)
  sys_call('echo WRITE_OWNER == Can become owner, reonfigure permissions', wmic_chk)
  sys_call('echo GENERIC_WRITE == Inherits SERVICE_CHANGE_CONFIG', wmic_chk)
  sys_call('echo GENERIC_ALL == Inherits SERVICE_CHANGE_CONFIG', wmic_chk)
  divider(wmic_chk)
  blank_line(wmic_chk)
  
  f = codecs.open(raw,"rb","utf-16")
  csvreader = csv.reader(f,delimiter=',')
  csvreader.next()
  csvreader.next()
  
  for row in csvreader:
    if len(row) < 2:
      continue
    service_name = row[1]
    raw_path = row[2]
    raw_path = raw_path.split(' -')[0]
    raw_path = raw_path.split('/')[0]
    service_path = raw_path.strip()
    if service_path == "":
      continue
    if service_path in path_list:
      continue
  
    path_list.append(service_path)
  
    sys_call('sc qc ' + service_name, wmic_chk)
    blank_line(wmic_chk)
    sys_call('accesschk.exe -ucqv "' + service_name + '" /accepteula', wmic_chk)
    blank_line(wmic_chk)
    sys_call('accesschk.exe -q "' + service_path + '" /accepteula', wmic_chk)
    divider(wmic_chk)
  
  f.close()
  os.remove(raw)
  
def main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument("-A", "--all", help="Run All Standard Enumeration Functions", action="store_true")
  parser.add_argument("-q", "--quick", help="Run Quick Privilege Escalation Enumeration (Start Here)", action="store_true")
  parser.add_argument("-b", "--basic", help="Run Basic System Information Enumeration", action="store_true")
  parser.add_argument("-n", "--network", help="Run Local Network Enumeration", action="store_true")
  parser.add_argument("-f", "--firewall", help="Run Windows Firewall Enumeration", action="store_true")
  parser.add_argument("-t", "--tasks", help="Run Tasks and Scheduled Actions Enumeration", action="store_true")
  parser.add_argument("-d", "--drivers", help="Run Windows Drivers Enumeration", action="store_true")
  parser.add_argument("-s", "--service", help="Run Windows Service Enumeration", action="store_true")
  parser.add_argument("-p", "--patch", help="Run Windows Patch Enumeration", action="store_true")
  parser.add_argument("-w", "--wmic", help="Run WMIC Check", action="store_true")
  args = parser.parse_args()
  
  if len(argv)==1:
    parser.print_help()
    sys.exit(1)
  
  check_dependencies()
  if args.basic or args.all:
    basic_enum()
  if args.network or args.all:
    network_enum()
  if args.firewall or args.all:
    firewall_enum()
  if args.tasks or args.all:
    tasks_sched_enum()
  if args.drivers or args.all:
    driver_enum()
  if args.service or args.all:
    service_enum()
  if args.patch or args.all:
    patch_enum()
  if args.quick or args.all:
    fast_priv_enum()
  if args.wmic:
    wmic_check()
  print "Done Processing!"
  
if __name__ == "__main__":
  main(sys.argv)

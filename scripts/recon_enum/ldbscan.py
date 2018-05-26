#!/usr/bin/env python

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time

def lbd(domain):
   domain = domain.strip()
   print "INFO: Running general ldb scans for " + domain
   # lbdSCAN = "lbd %s"  % (domain)
   # results = subprocess.check_output(lbdSCAN, shell=True)
   # lines = results.split("\n")
   lines = subprocess.check_output(['ldb',domain]).split("\n")
   for line in lines:
      line = line.strip()
      if ("Load-balancing" in line) and not ("NOT" in line):
         print (line)
      if ("does NOT use Load-balancing" in line):
         print (line)
      else:
         return
   return

if __name__=='__main__':
   f = open('results/exam/targets.txt', 'r') # CHANGE THIS!! grab the alive hosts from the discovery scan for enum
					     # Also check Nmap user-agent string, should be set to Firefox
   for domain in f:
       jobs = []
       p = multiprocessing.Process(target=lbd, args=(domain,))
       jobs.append(p)
       p.start()
   f.close()

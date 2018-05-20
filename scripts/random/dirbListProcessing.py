#!/usr/bin/env python
import os
import sys
import subprocess

#This was used with specific directories: probable and secProb
#probable was comprised of most of the files in "separate"
#secProb was comprised of most of the files in SecLists/Web-Content
#For this to work, update chdr (currently pointed to Web/AllWebLists)
#And call the functions pointing to your dir of files

def help():
    print " USAGE TEXT HERE "
    print "Process all lists in a folder, combines, uniqes, and outputs."
    print "Process previous list, uniques, removes extensions, removes first '/', and outputs."
    print "From there, it will go into the same folder and make separate lists for all extensions"

os.chdir("/root/lists/Web/AllWebLists")
if not os.path.exists("processed"):
    os.makedirs("processed")
if not os.path.exists("processed/extensions"):
    os.makedirs("processed/extensions")

extensions=".asp",".aspx",".bat",".c",".cfm",".cgi",".com",".dll",".exe",".htm",".html",".inc",".jhtml",".jsa",".jsp",".log",".mdb",".nsf",".php",".phtml",".pl",".reg",".sh",".shtml",".sql",".txt",".xml"

#elimExt from a single file
def elimExt(filename):
  final1 = set()
  f=open(str(filename))
  for line in f:
    for ext in extensions:
      if ext in line:
        tmp = line.split(ext)[0]
        if "\n" in tmp:
          final1.add(str(tmp[-1]))
        else:
          final1.add(str(tmp))
      else:
        if "\n" in line:
          final1.add(str(line[-1]))
        else:
          final1.add(str(line))
  f.close()
  return sorted(final1)

#write the ouput from a set,
def writeRet(ret, out):
  g=open(str(out), 'w')
  for line in ret:
        if (line != ""):
            if (line[0] == "/"):
                g.write(str(line[1:])+"\n")
            else:
                g.write(str(line)+"\n")
  g.close()

#pass full path of dir, make extensioned lists from folder
def makeExtensionLists(dir, name):
  for ext in extensions:
    ext_no_dot = ext.split(".")[1]
    comuni = "grep -ir '\.%s' %s/* | cut -d ':' -f2 | sort | uniq > /root/lists/Web/AllWebLists/processed/%s_%s_extensions.txt" % (ext_no_dot, dir, name, ext_no_dot)
    results = subprocess.check_output(comuni, shell=True)

#pass full path of dir
def comUniFromDir(dir, name):
    comuni = "awk '!a[$0]++' %s/* > /root/lists/Web/AllWebLists/processed/%s_comb.txt" % (dir, name)
    results = subprocess.check_call(comuni, shell=True)

def comUniExtensionFiles(dir):
    cwd = os.getcwd()
    os.chdir(dir)
    for ext in extensions:
        files = os.listdir(dir)
        finalString = ""
        ext_no_dot = ext.split(".")[1]
        ar = []
        for textFile in files:
            #print "Trying: %s" % (textFile)
            filename = "_%s_" % (ext_no_dot)
            fileSplit = textFile.split("_")
            #print "IF: %s in %s" % (filename, textFile)
            if (filename in textFile):
                #print "Append: %s" % textFile
                ar.append(textFile)
        for ext_file in ar:
            finalString = finalString + " " + ext_file
        if finalString == "":
            pass
        else:
            comuni = "awk '!a[$0]++' %s > /root/lists/Web/AllWebLists/processed/extensions/%s_extension_comb.txt" % (finalString, ext_no_dot)
            #print "Finalstring: %s" % finalString
            #print "Trying command: %s" % comuni
            results = subprocess.check_call(comuni, shell=True)
            for ext_file in ar:
                try:
                    os.unlink(ext_file)
                except:
                    pass
    os.chdir(cwd)



comUniFromDir("/root/lists/Web/AllWebLists/probable", "probable")
comUniFromDir("/root/lists/Web/AllWebLists/secProb", "secProb")

writeRet(elimExt("processed/probable_comb.txt"), "processed/probable_no_ext.txt")
writeRet(elimExt("processed/secProb_comb.txt"), "processed/secProb_no_ext.txt")

makeExtensionLists("/root/lists/Web/AllWebLists/probable", "probable")
makeExtensionLists("/root/lists/Web/Web-Content", "web_content")

comUniExtensionFiles("/root/lists/Web/AllWebLists/processed")

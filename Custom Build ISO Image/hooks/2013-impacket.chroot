#!/bin/bash

# Get the latest impacket and all scripts from github

mkdir -p /opt/impacket 2>/dev/null
wget https://github.com/CoreSecurity/impacket/archive/master.zip -O /tmp/impacket.zip
last=$(pwd)
cd /tmp && unzip /tmp/impacket.zip ** rm /tmp/impacket.zip
cd /opt/impacket && mv /tmp/impacket-master/* -t /opt/impacket && chmod +x setup.py && ptyhon setup.py install
cd $last

# OSCPRepo

This is a list of resources and scripts that I have been gathering (and continuing to gather) in preparation for the OSCP. These are all free resources on the Internet, so feel free to use however you want to help you in your studies/reference material. If I have taken information from you or your work, please let me know so that I can acknowledge you.

# Three Primary Functions
UsefulCommands.nbk

Nearly everything important is in the KeepNote notebook 'Usefulcommands'. It started as a reference using KeepNote since it was easy, relatively hassle free, and part of the default install on Kali. The Windows version is great as well. It contains methodologies, links to scripts, tools, links to popular resources, reference guides on numerous subjects, and more. 

Recon_Scan.py

A popular script, it's goal is to run unicornscan, identify popular services, pass that discovery on to other scripts for detailed enumeration etc, and then perform a full nmap scan (in case anything was missed). This functionality could probably be imported into Sparta (a cool gui tool). It's also probably worse than Vanquish. For now, it get's the job done with a single ./reconscan.py. It is designed to run multithreaded against multiple targets simultaneously if network bandwidth allows. 

Reconscan now uses gobuster as its directory brute forcing tool. Please ensure it is in your path. Dirb is still available, but you have to pass the option to dirbEVERYTHING.py or use dirb.py.

Reconscan.py has the ability to run unicornscan, tens of nmap scripts, gobuster/dirb, nikto, whatweb, hydra, and so much more. Written in python, it is easy to change, configure (if wanted), and even run modules separately against a target. Unicornscan will finish and write its output first to allow you to manually look at a target/around its web interface while the rest of the scan is finishing. 

Place 'scripts' and 'lists' in the /root/ directory and it should handle the rest.

BookmarkList.nbk

Going through list after list of compiled resource, github pages, etc, and I wanted an organized list of bookmarks and references I could go back to. It contains organized links from two of the largest bookmark sources I've found. More will be added. Links will probably move out of Usefulcommands and into BookmarkList over time. 

# Other Stuff

Folders mostly speak for themselves. Lists contains a bunch of wordlists. Some methodologies and cheat sheets are downloaded. Some tools and scripts are kept local until they become integrated. ListOfSoftwareToAptGet.txt contains some information on setup that a user might want to consider when this repo is cloned from a default Kali installation.

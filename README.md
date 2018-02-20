# OSCPRepo

This is a list of resources and scripts that I have been gathering (and continuing to gather) in preparation for the OSCP. These are all free resources on the Internet, so feel free to use however you want to help you in your studies/reference material. If I have taken information from you or your work, please let me know so that I can acknowledge you.

# Three Primary Functions
UsefulCommands.nbk

Nearly everything important is in the KeepNote notebook 'Usefulcommands'. It started as a reference using KeepNote since it was easy, relatively hassle free, and part of the default install on Kali. The Windows version is great as well. It contains methodologies, links to scripts, tools, links to popular resources, reference guides on numerous subjects, and more. Over time, I have been moving many of the references to BookmarkList.

Recon_Scan.py

A popular script, it's goal is to run unicornscan, identify popular services, pass that discovery on to other scripts for detailed enumeration etc, and then perform a full nmap scan (in case anything was missed). This functionality could probably be imported into Sparta (a cool gui tool). It's also probably worse than Vanquish. For now, it get's the job done with a single ./reconscan.py. It is designed to run multithreaded against multiple targets simultaneously if network bandwidth allows. 

Reconscan.py has the ability to run unicornscan, tens of nmap scripts, gobuster/dirb, nikto, whatweb, hydra, and so much more. Written in python, it is easy to change, configure (if wanted), and even run modules separately against a target. Unicornscan will finish and write its output first to allow you to manually look at a target/around its web interface while the rest of the scan is finishing. 

There is now a setup.sh script in /scripts folder that will clone some required repositories, move folders into place, and should make reconscan ready to go.

BookmarkList.nbk

Going through list after list of compiled resource, github pages, etc, and I wanted an organized list of bookmarks and references I could go back to. It contains organized links from two of the largest bookmark sources I've found. More will be added. Links will probably move out of Usefulcommands and into BookmarkList over time. 

# Other Stuff

Folders mostly speak for themselves. Lists contains a bunch of wordlists. Some methodologies and cheat sheets are downloaded. Some tools and scripts are kept local until they become integrated. ListOfSoftwareToAptGet.txt contains some information on setup that a user might want to consider when this repo is cloned from a default Kali installation.

GetGitHubStars

A quick powershell script that can grab a user's starred repositories and output them to a csv. I wanted to combine them with my own personal comments for a list of all my stars for easier sorting, tagging, etc. Edit commentsToJSON and they will be added to output.csv. Additionally, the script can go and get trending repositories. TODO: add function to star repos in the script; add function to 'blacklist' popular repositories that you no longer want to see. 

# Latest Changes

20 Feb 18: At the least, httpenum, httpsenum, and dirbustEVERYTHING should be able to handle port changes (ie scan and output different ports manually). httpenum and httpsenum might be pulled out and made their own modules. dirbustEVERYTHING now scans for .php and .html extensions and runs cewl to generate a new list for additional enumeration. 

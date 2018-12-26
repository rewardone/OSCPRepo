# OSCPRepo

This is a list of resources and scripts that I have been gathering (and continuing to gather) in preparation for the OSCP. Now achieved, this repo will continue to grow it's resources for future certifications. These are all free resources on the Internet, so feel free to use however you want to help you in your studies/reference material. If I have taken information from you or your work, please let me know so that I can acknowledge you.

Do you have a million bookmarks saved? Do all of those bookmarks contain unique information? Github repos starred for later?
I wanted to actually compose and provide a compilation of all of these resources into a single organized notebook. No more need for bookmarked links. No need to open a web browser. Everything will be here for you.

# Keepnote

Keepnote continues to be my main notebook application. Included with Kali and has a client for Windows and MacOS.
CherryTree has many useful features; however, I (personally) want tabbed notebooks (instead of multiple instances of CherryTree) and the ability to Cut/Copy/Paste nodes from one notebook to another. These are on the developers wish list. CherryTree can still import any of my Keepnote folders. Just give it enough time to import. Note that the nodes will be jumbled due to the import, but an alphabetical sort ascending will fix most of it.

# Notable Resources
UsefulCommands.nbk

It contains methodologies, commands, and interesting file locations. This has been moving more and more into BookmarkList. The goal will be to ensure UsefulCommands is just that. UsefulCommands. Man pages, reference material, etc. For walkthroughs and detailed information, head to BookmarkList.

BookmarkList.nbk

List after list of compiled bookmarks, github pages, blogs, OSCP reviews, tools, and a lot more compiled into an organized list of bookmarks and references I could go back to (offline). Sources for all resources are still there so you can read the material directly if you desire. This is a work in progress and there are sections I have not read through yet and made child-nodes for yet, but it is still incredibly extensive with more work being done (almost) every day (look at the commit history!)

![Parent Nodes](https://github.com/rewardone/OSCPRepo/blob/master/KeepNotes/BookmarkList.PNG)

Recon_Scan.py

A popular script, it's goal is to run nmap, identify popular services, pass that discovery on to other scripts for detailed enumeration etc, and then perform a full nmap scan (in case anything was missed). Partial Sparta integration is complete, and setup.sh will move those files for you. Also check out Vanquish. From the CLI, reconscan gets the job done with a single ./reconscan.py. It is designed to run multithreaded against multiple targets simultaneously if network bandwidth allows. You can adjust the min-rate in the scripts.

There is now a setup.sh script in /scripts folder that will clone some required repositories, move folders into place, and should make reconscan ready to go.


# Other Stuff

Folders mostly speak for themselves. Lists contains a bunch of wordlists (setup.sh will download more). Some methodologies and cheat sheets are downloaded. Some tools and scripts are kept local until they become integrated. You can find local enumeration checkers and privesc checkers in their respective folders (note that these are snapshots and not necessarily the most up-to-date versions of these scripts).

GetGitHubStars

A quick powershell script that can grab a user's starred repositories and output them to a csv. I wanted to combine them with my own personal comments for a list of all my stars for easier sorting, tagging, etc. Edit commentsToJSON and they will be added to output.csv. Additionally, the script can go and get trending repositories. TODO: add function to star repos in the script; add function to 'blacklist' popular repositories that you no longer want to see.

# Latest Changes
26 Dec 18: OSCP achieved. This marks a milestone in the repo that all information needed to pass the OSCP is included here in the relevant sections. Although information cannot replace hands-on practice, if you need a place to start diving into a particular piece deeper, it's here or linked here. Reconscan hasn't necessarily 'expanded' as much as it can, but it's been crucial in the labs, exams, hackthebox, and ctfs. Even if you don't want to use the script, look at the modules for commands you should include in your methodology. 

22 Aug 18: BlackHat and Defcon were a blast. There was a lot of bugfixing going on. Scripts are becoming more modular and nicer to work with (say hello to nfs and ldap recon). dirbustEVERYTHING has received a lot of attention including the integration of wfuzz and parameth. You can check which nmap scripts are run and which script they are in with the 'nmap to recon scan mapping' sheet (partially complete because I overwrote the master, but I will finish it again later). Some lists/payloads have been tweaked. 

21 May 18: Unicornscan and python mutliprocessing don't go well together. Changed everything to Nmap. It's advisable to adjust --min-rate as needed. Some modules added. Banners. dirbEverything logic and wordlists all updated. Nmap has also been changed to run full connect scans sT. Syn scans are too identifiable (though the speed probably doesn't help this script).

10 Apr 18: Updated LinEnum. Most enumeration scripts are not bad even if they haven't been updated in a few years. I was partial to linuxprivchecker.py for a long time; however, I wanted something just in case a machine didn't have python installed. I really like the idea behind pentestmonkey's linux-privesc-check master branch. I even thought about putting work into Lynis or creating a 'pentest' profile. Eventually I chose to update LinEnum due to it being a single file, relatively updated, and already has features like reporting and verbosity level (thorough). Many additional checks, updated version number, etc. Please let me know if you want additional checks included or find bugs. Enjoy.

28 Mar 18: Some minor updates. Included aliverecon which just does an nmap ping scan. Included nbtscan for additional coverage in smbrecon. Reconscan will now backup everything in the exam folder and move it every time it's launched. Please ensure you always have a targets.txt in place.

4 Mar 18: dirTrav.py as a wrapper for dotdotpwn. It requires a file with a list of URLs to attempt. If it finds anything, it will grab the files listed in the default list (lists/Personal/Misc\ Lists/DirTrav/linux_all.txt). Windows support has not been tested. This script requires a manual invocation. I did not want it to launch automatically from the gobuster results (since there is always a lot of junk and would just increase dirTrav time). Special note, setup.sh alters dotdotpwn so that pressing 'Enter' is not required to start the scan.

20 Feb 18: At the least, httpenum, httpsenum, and dirbustEVERYTHING should be able to handle port changes (ie scan and output different ports manually). httpenum and httpsenum might be pulled out and made their own modules. dirbustEVERYTHING now scans for .php and .html extensions and runs cewl to generate a new list for additional enumeration.

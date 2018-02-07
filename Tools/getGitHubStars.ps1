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
        if($finalObject.tags -eq $null) {
            $finalObject += New-Object -TypeName psobject -Property @{full_name=$starbject.full_name; name=$starbject.name; svn_url=$starbject.svn_url; description=$starbject.description; comment=$starbject.homepage; tags=" "}
        }
    }
    $finalObject | Select name, full_name, svn_url, comment, description, tags | Export-Csv -Path .\output.csv
    "Done `n`n"
    mainMenu
}

function getGitHubTrending{
#get trending 

#display if trending for month
#display if trending for a week
#display if trending for a day

#remove trending repositories if they are on a user-set blacklist

#would you like to star any of these? 
#would you like to add any of these to blacklist?
}



function mainMenu {
    
    "1 Get GitHub Stars"
    "2 Show trending GitHub repositories"
    "`n"

    "0 Exit"
    $arg = Read-Host -Prompt 'Choose an option'
    Switch ($arg){
        1 {getGitHubStars}
        2 {getGitHubTrending}


        0 {Break}
    }
   


}

mainMenu
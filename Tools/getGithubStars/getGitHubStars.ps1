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
#$allStars | Select full_name, svn_url, description

# Add custom personal descriptions from a list
#psuedo
#iterate through descriptions
#for descriptions, grab index where match
 #write to new object
#write to file
$descriptionFile = Import-Csv '.\Documents\tmp\testtoJSON.csv'
$finalObject = $null
$finalObject = @()
$allStars | ForEach-Object {
    $starbject = $_
    $descriptionFile | ForEach-Object {
        if(($_.software) -eq ($starbject.name)){
            $finalObject += New-Object -TypeName psobject -Property @{full_name=$starbject.full_name; svn_url=$starbject.svn_url; description=$starbject.description; comment=$_.description}
        }
    }
    $finalObject += New-Object -TypeName psobject -Property @{full_name=$starbject.full_name; svn_url=$starbject.svn_url; description=$starbject.description; comment=$starbject.homepage}
}
$finalObject | Select full_name, svn_url, comment, description | Export-Csv -Path .\output.csv
#$allStars.IndexOf(($allStars | Where-Object -Property "name" -EQ "discover"))
#$file3 = Import-Csv .\testtoJSON.csv

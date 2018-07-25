function TestFor-StickyKey {

    Write-Host

    $cmdHash = Get-FileHash -LiteralPath $env:windir\System32\cmd.exe
    $psHash = Get-FileHash -LiteralPath $env:windir\System32\WindowsPowerShell\v1.0\powershell.exe
    $explorerHash = Get-FileHash -LiteralPath $env:windir\explorer.exe
    $sethcHash = Get-FileHash -LiteralPath $env:windir\System32\sethc.exe
    $oskHash = Get-FileHash -LiteralPath $env:windir\System32\osk.exe
    $narratorHash = Get-FileHash -LiteralPath $env:windir\System32\Narrator.exe
    $magnifyHash = Get-FileHash -LiteralPath $env:windir\System32\Magnify.exe
    $displayswitchHash = Get-FileHash -LiteralPath $env:windir\System32\DisplaySwitch.exe

    if ($cmdHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $sethcHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "sethc.exe: $($sethcHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $oskHash.Hash) {

        Write-Output "Possible backdoor found. osk.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "osk.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with cmd.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "narrator.exe: $($narrator.Hash)"
        Write-Host

        }

    if ($explorerHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "narrator.exe: $($narratorHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $narratorHash.Hash) {

        Write-Output "Possible backdoor found. narrator.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "narrator.exe: $($oskHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $magnifyHash.Hash) {

        Write-Output "Possible backdoor found. magnify.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

     if ($explorerHash.Hash -eq $magnifycHash.Hash) {

        Write-Output "Possible backdoor found. sethc.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $magnifyHash.Hash) {

        Write-Output "Possible backdoor found. magnify.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "magnify.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    if ($cmdHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "cmd.exe: $($cmdHash.Hash)"
        Write-Output "displayswitch.exe: $($displayswitchHash.Hash)"
        Write-Host

        } 

    if ($explorerHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with explorer.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "explorer.exe: $($explorerHash.Hash)"
        Write-Output "displayswitch.exe: $($displayswitchHash.Hash)"
        Write-Host

        } 

    if ($psHash.Hash -eq $displayswitchHash.Hash) {

        Write-Output "Possible backdoor found. displayswitch.exe replaced with powershell.exe"
        Write-Host
        Write-Output "Checked the following hashes:"
        Write-Output "powershell.exe: $($psHash.Hash)"
        Write-Output "displayswitch.exe: $($magnifyHash.Hash)"
        Write-Host

        } 

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'
    $nameSethc = 'sethc.exe'
    $nameUtilman = 'utilman.exe'
    $property = 'Debugger'

    if (Test-Path -LiteralPath ($key + $nameSethc)) {
          
          $tb = Get-Item -LiteralPath ($key + $nameSethc)
          
          if ($tb.GetValue($property) -ne $null) {

                Write-Output "Possible backdoor identified at:"
                Get-Item -LiteralPath ($key + $nameSethc)
                Write-Output ""
                Write-Output "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                Write-Host
            
            }

    }

    if (Test-Path -LiteralPath ($key + $nameUtilman)) {
          
          $tb = Get-Item -LiteralPath ($key + $nameUtilman)
          
          if ($tb.GetValue($property) -ne $null) {

                Write-Output "Possible backdoor identified at:"
                Get-Item -LiteralPath ($key + $nameUtilman)
                Write-Output ""
                Write-Output "Investigate to determine if value of Debugger property set to system-level shell 
                - e.g., cmd.exe"
                Write-Host
            
            }

    }

}

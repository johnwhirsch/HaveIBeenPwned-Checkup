param([Parameter(Mandatory=$True)][string]$pwnedrecords)

# Get the JSON file no matter where it is
if($pwnedrecords -like "http*"){
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "Attempting to get records from web JSON: $($pwnedrecords)";
    $breachesjson = [System.Net.WebClient]::new().DownloadString("$pwnedrecords") | ConvertFrom-Json
}
elseif($pwnedrecords -like "\\*"){ $breachesjson = Get-Content "Microsoft.PowerShell.Core\FileSystem::$($pwnedrecords)" }
else{ $breachesjson = Get-Content $pwnedrecords }


# This will set how many days back the script should start searching for old passwords
[int]$daysback = 30;

$allAdUsers = $(get-aduser  -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -properties * )

$badbreachcount=0;

foreach($breach in $breachesjson.BreachSearchResults){

    $badbreachs = $breach.Breaches | ? { ($_.Description -like "*credential*" -or $_.Description -like "*password*") -and $_.Description -notlike "*no password*" }
    if($badbreachs.count -gt 0 -or $($breach.Pastes).count -gt 0){

        if(( $adusercheck = $allAdUsers | ? { $_.SamAccountName -eq $($breach.Alias) } )){         
            

            foreach($badbreach in $badbreachs){                   
                try{
                    if($adusercheck.PasswordLastSet -lt [datetime]$badbreach.BreachDate -and $adusercheck.Enabled -eq $true){
                        $badbreachcount = $badbreachcount + 1;
                        $csvout = new-object PSObject
                        $csvout | add-member -membertype NoteProperty -name "UserAccount" -value $($adusercheck.SamAccountName)
                        $csvout | add-member -membertype NoteProperty -name "UserDescription" -value $($adusercheck.DisplayName)
                        $csvout | add-member -membertype NoteProperty -name "LastPwChange" -value $($adusercheck.PasswordLastSet)
                        $csvout | add-member -membertype NoteProperty -name "BreachTitle" -value $($badbreach.Title)
                        $csvout | add-member -membertype NoteProperty -name "BreachDate" -value $($badbreach.BreachDate)
                        $csvout | add-member -membertype NoteProperty -name "BreachDescription" -value $($badbreach.Description)
                        $csvout | Export-Csv "$($PSScriptRoot)\BreachesReport.csv" -Append -notypeinformation

                        write-host "Found breach for user [ " -ForegroundColor Red -NoNewline;
                        write-host "$($adusercheck.SamAccountName) | $($adusercheck.DisplayName)" -ForegroundColor Yellow -NoNewline;
                        write-host " ] " -ForegroundColor Red -NoNewline;
                        write-host "Last PW change: " -ForegroundColor Red -NoNewline;
                        write-host "$($adusercheck.PasswordLastSet)" -foregroundcolor yellow;

                        Write-Host "[ " -ForegroundColor Red -NoNewline;
                        Write-Host "$($badbreach.Title) | $($badbreach.BreachDate)" -ForegroundColor Yellow -NoNewline;
                        Write-Host " ] " -ForegroundColor Red -NoNewline;
                        Write-Host "$($badbreach.Description)"
                    }
                }catch{ Write-Output "Unable to find breach alias against AD."; continue }
            }

            #work in progress, not functional yet
            if($($badbreach.Pastes).count -gt 0){
                           
                foreach($paste in $badbreach.Pastes){
                    Write-Host "[" -ForegroundColor Red -NoNewline;
                    Write-Host "$($paste.Source) | $($paste.Date)" -ForegroundColor Yellow -NoNewline;
                    Write-Host "]" -ForegroundColor Red -NoNewline;
                    Write-Host "User credentials were found pasted on $($paste.Source)"

                }
                Write-Host "";
            }
        }
    
    }

}


Write-Host "Total bad breachs in the last $($daysback) days: $($badbreachcount)" -ForegroundColor Yellow -BackgroundColor DarkRed

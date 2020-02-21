# To use, run this powershell file with -pwnedrecords argument
# Examples:
# .\hibp-breaches.ps1 -pwnedrecords "https://haveibeenpwned.com/DomainSearch/bbe6cc98ea31222222222d7ab9f0997/Json"
# .\hibp-breaches.ps1 -pwnedrecords "\\contoso.com\shares\report.json"
# .\hibp-breaches.ps1 -pwnedrecords "C:\Users\Contoso\Desktop\report.json"
#

param([Parameter(Mandatory=$True)][string]$pwnedrecords)

if($pwnedrecords -like "http*"){
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "Attempting to get records from web JSON: $($pwnedrecords)";
    $breachesjson = [System.Net.WebClient]::new().DownloadString("$pwnedrecords") | ConvertFrom-Json
}
elseif($pwnedrecords -like "\\*"){ $breachesjson = Get-Content "Microsoft.PowerShell.Core\FileSystem::$($pwnedrecords)" | ConvertFrom-Json }
else{ $breachesjson = Get-Content $pwnedrecords | ConvertFrom-Json }

$allAdUsers = $(get-aduser  -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -properties * )

$badbreachcount=0;
$badpastecount=0;

foreach($breach in $breachesjson.BreachSearchResults){

    $badbreaches = $breach.Breaches | ? { ($_.Description -like "*credential*" -or $_.Description -like "*password*") -and $_.Description -notlike "*no password*" }
    if($badbreaches.count -gt 0){

        if(( $adusercheck = $allAdUsers | ? { $_.SamAccountName -eq $($breach.Alias) } )){         
            

            foreach($badbreach in $badbreaches){                   
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
           
        }
    
    }

}
foreach($breach in $breachesjson.PasteSearchResults){
    if($($breach.Pastes).count -gt 0){
        if(( $adusercheck = $allAdUsers | ? { $_.SamAccountName -eq $($breach.Alias) } )){
         
            foreach($paste in $breach.Pastes){

                if($($paste.Date).length -eq 0){ $pasteDate = "2222-01-01T00:13:37Z"; }
                else{ $pasteDate = $paste.Date }
                if($adusercheck.PasswordLastSet -lt [datetime]$pasteDate -and $adusercheck.Enabled -eq $true){
                    $badpastecount=$badpastecount+1;
                    if($pasteDate -eq "2222-01-01T00:13:37Z"){ $pasteDate = "Unknown Post Date" }

                        $csvout = new-object PSObject
                        $csvout | add-member -membertype NoteProperty -name "UserAccount" -value $($adusercheck.SamAccountName)
                        $csvout | add-member -membertype NoteProperty -name "UserDescription" -value $($adusercheck.DisplayName)
                        $csvout | add-member -membertype NoteProperty -name "LastPwChange" -value $($adusercheck.PasswordLastSet)
                        $csvout | add-member -membertype NoteProperty -name "BreachTitle" -value "PASTED - $($paste.Source)"
                        $csvout | add-member -membertype NoteProperty -name "BreachDate" -value $($pasteDate)
                        $csvout | add-member -membertype NoteProperty -name "BreachDescription" -value "User credentials were found pasted on $($paste.Source)"
                        $csvout | Export-Csv "$($PSScriptRoot)\BreachesReport.csv" -Append -notypeinformation

                        write-host "Found breach for user [ " -ForegroundColor Red -NoNewline;
                        write-host "$($adusercheck.SamAccountName) | $($adusercheck.DisplayName)" -ForegroundColor Yellow -NoNewline;
                        write-host " ] " -ForegroundColor Red -NoNewline;
                        write-host "Last PW change: " -ForegroundColor Red -NoNewline;
                        write-host "$($adusercheck.PasswordLastSet)" -foregroundcolor yellow;


                        Write-Host "[ " -ForegroundColor Red -NoNewline;
                        Write-Host "$($paste.Source) | $($pasteDate)" -ForegroundColor Yellow -NoNewline;
                        Write-Host " ] " -ForegroundColor Red -NoNewline;
                        Write-Host "User credentials were found pasted on $($paste.Source)"
                }

            }
        }
    }
}

Write-Host "Total bad breaches found: $($badbreachcount)" -ForegroundColor Yellow -BackgroundColor DarkRed
Write-Host "Total bad pastes found: $($badpastecount)" -ForegroundColor Yellow -BackgroundColor DarkRed

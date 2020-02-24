# HaveIBeenPwned-Checkup
Check current AD password age vs  JSON HaveIBeenPwned Report

To use, run this powershell file with -pwnedrecords argument

Examples:

.\hibp-breaches.ps1 -pwnedrecords "https://haveibeenpwned.com/DomainSearch/bbe6cc98ea31222222222d7ab9f0997/Json"

.\hibp-breaches.ps1 -pwnedrecords "\\\\contoso.com\shares\report.json"

.\hibp-breaches.ps1 -pwnedrecords "C:\Users\Contoso\Desktop\report.json"


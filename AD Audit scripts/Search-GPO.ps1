
Get-Gpo -all | where-object { $_.DisplayName -like "*snmp*" }

Get-Gpo -all | export-csv GPO$date.csv -NoTypeInformation

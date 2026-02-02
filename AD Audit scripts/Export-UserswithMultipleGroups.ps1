set-location F:\SCRIPTS\O365
$Date = get-date -Format "yyyy-MM-dd-HH-mm"
get-aduser -Filter * -Properties memberof | Where-Object { $_.memberof -like "*G_BRP_AzureAD_License_M365_E3*" -and $_.memberof -like "*G_BRP_AzureAD_License_O365_ProPlus*" } | export-csv "double-office-$date.csv" -NoTypeInformation

& .\double-office-$date.csv

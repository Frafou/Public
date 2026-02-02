#Get-ChildItem .\Report\EventReport.htm | remove-item
$date = Get-Date -Format yyyyMMdd-hhmmss
$DCs = Get-ADDomainController -Filter * | Sort-Object -Unique Name
foreach ($DC in $DCs) {
	Write-Output "DC: $($DC.Name)"

	if	(Test-Connection $DC) {

		#Generates Event Report
		Write-Output "`tGenerates Application Event Report"
		Get-EventLog -LogName Application -ComputerName $DC -Newest 600 | Sort-Object -Descending Source | ConvertTo-Html -Title EventReport -pre "Application_Errors $($DC.name)" | Out-File .\Report\Application-EventReport-$($DC.name)-$date.html

		Write-Output "`tGenerates Security Event Report"
		Get-EventLog -LogName Security  -ComputerName $DC -Newest 600 | Sort-Object -Descending Source | ConvertTo-Html -pre "Security_Errors $($DC.name)" | Out-File  .\Report\Security-EventReport-$($DC.name)-$date.html
	} else {
		Write-Error "Unable to connect to DC: $($DC.name)"

	}

}

	Write-Output "Export Completed"



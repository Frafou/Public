<#
.SYNOPSIS
	Outputs file system directory statistics.

.DESCRIPTION
	Will check the replication status and if there are failures will send an email to the Assigned Addresses.
    ** Requires Repadmin from the Windows resource Kit accessible in the default path **

.PARAMETER Path
	None

.INPUTS
	None

.OUTPUTS
	Email results

.Example
    AD Replication Status.ps1

.Notes
    NAME:
    AUTHOR:  Maish Saidel-Keesing
    DATE  : 2010/04/27
    Last Edit:2019/04/11
    KEYWORDS:
.Link
	HTTP://www.

 #Requires -Version 2.0
 #>

$LogDate = Get-Date -Format yyyyMMdd-HHmmss

$htmlreport = $null
$htmlbody = $null
$htmlfile = ".\report\AD Replication Status-$LogDate.html"
$spacer = "<br />"


#Collect the replication info

#Check the Replication with Repadmin
$workfile = repadmin.exe /showrepl * /csv
$results = ConvertFrom-Csv -InputObject $workfile | Where-Object { $_.'Number of Failures' -ge 1 }


#Here you set the tolerance level for the report
$results = $results | Where-Object { $_.'Number of Failures' -gt 1 }

if ($null -ne $results ) {
    $results = $results | Select-Object "Source DC", "Naming Context", "Destination DC" , "Number of Failures", "Last Failure Time", "Last Success Time", "Last Failure Status" | ConvertTo-Html
}
else {
    $results = "There were no Replication Errors"
}

#Send-MailMessage -From $from -To $to -Subject "Daily Forest Replication Status" -SmtpServer "mailhost.Domain.local" -BodyAsHtml ($results | Out-String)


$Results | Out-File $htmlfile

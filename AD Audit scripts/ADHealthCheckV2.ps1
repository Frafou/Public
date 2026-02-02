#Requires -Version 5.1
<#
.SYNOPSIS
  AD Health Status
  Status: Ping,Netlogon,NTDS,DNS,DCdiag Test(Replication,sysvol,Services), Advertising

.DESCRIPTION
	Status of the following services for all DCs: Ping,Netlogon,NTDS,DNS,DCdiag Test(Replication,sysvol,Services), Advertising

.PARAMETER Timeout
	Specifies the maximum wait time for each job, in seconds. The default value, -1, indicates that the cmdlet waits until the job finishes. The timing starts when you submit the Wait-Job command, not the Start-Job command.

	If this time is exceeded, the wait ends and execution continues, even if the job is still running. The command does not display any error message.

.PARAMETER Smtphost
	SMTP Server.

.PARAMETER From
	From Address.

.PARAMETER EmailReport
	E-mail Address/Addresses(separated by comma) for report.

.INPUTS
	None

.OUTPUTS
	Log:  $ScriptPath\$ScriptName-MMddyyyyHHmm.log

.Example
    ADHealthCheckV2.ps1 -verbose

.Notes
    NAME:			ADHealthCheckV2.ps1
    AUTHOR:		Vikas Sukhija
		CREATED:	2021-05-03

	Version History
	1.0 Original Version
	2.0 version with parameters to make it more generic

	.Link
	https://www.powershellgallery.com/packages/ADHealthCheckV2/1.0/Content/ADHealthCheckV2.ps1
	https://techwizard.cloud/2021/05/04/active-directory-health-check-v2/
	https://techwizard.cloud/2021/05/04/active-directory-health-check-v2/

.GUID 30c7c087-1268-4d21-8bf7-ee25c37459b0

.DESCRIPTION
    Date: 12/25/2014
    AD Health Status
    Status: Ping,Netlogon,NTDS,DNS,DCdiag Test(Replication,sysvol,Services)
    Update: Added Advertising
    Update: 5/3/2021 version2 with parameters to make it more generic


#>
#----------------  Parameters ------------
Param(

	[Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Path',
		ValueFromPipeline = $true,
		ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Enter Timeout in seconds')]
	[ValidateNotNullOrEmpty()]
	[Int32]$Timeout = -1,

	[Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Path',
		ValueFromPipeline = $true,
		ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Enter SMTP Server')]
	[ValidateNotNullOrEmpty()]
	[string[]]
	$Smtphost,

	[Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Path',
		ValueFromPipeline = $true,
		ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Enter From Address')]
	[ValidateNotNullOrEmpty()]
	[string[]]
	$EmailFrom,


	[Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'Path',
		ValueFromPipeline = $true,
		ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Enter To Address')]
	[ValidateNotNullOrEmpty()]
	[string[]]
	$EmailTo

)

###########################Define Variables##################################
if ($PSVersionTable.PSVersion.Major -eq 5) {
	Write-Output 'You are running PowerShell version 5.'
} else {
	Write-Output 'You are NOT running PowerShell version 5.'
	Return 1
}

$Date = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$Forest = (Get-ADDomain).forest
if ($EmailTo ) {
	$EmailTo = $EmailTo -split ','
}



$Report = "$ScriptPath" + '\' + "\report\ADReport-$forest-$date.html"

if ((Test-Path $Report) -like $false) {
	New-Item $Report -type file
}

###############################HTml Report Content############################
Clear-Content $Report
Add-Content $Report '<html>'
Add-Content $Report '<head>'
Add-Content $Report "<meta http-equiv='Content-Type' content='text/html; charset=iso-8859-1'>"
Add-Content $Report '<title>AD Status Report</title>'
Add-Content $Report '<STYLE TYPE="text/css">'
Add-Content $Report '<!--'
Add-Content $Report 'td {'
Add-Content $Report 'font-family: Tahoma;'
Add-Content $Report 'font-size: 11px;'
Add-Content $Report 'border-top: 1px solid #999999;'
Add-Content $Report 'border-right: 1px solid #999999;'
Add-Content $Report 'border-bottom: 1px solid #999999;'
Add-Content $Report 'border-left: 1px solid #999999;'
Add-Content $Report 'padding-top: 0px;'
Add-Content $Report 'padding-right: 0px;'
Add-Content $Report 'padding-bottom: 0px;'
Add-Content $Report 'padding-left: 0px;'
Add-Content $Report '}'
Add-Content $Report 'body {'
Add-Content $Report 'margin-left: 5px;'
Add-Content $Report 'margin-top: 5px;'
Add-Content $Report 'margin-right: 0px;'
Add-Content $Report 'margin-bottom: 10px;'
Add-Content $Report ''
Add-Content $Report 'table {'
Add-Content $Report 'border: thin solid #000000;'
Add-Content $Report '}'
Add-Content $Report '-->'
Add-Content $Report '</style>'
Add-Content $Report '</head>'
Add-Content $Report '<body>'
Add-Content $Report "<table width='100%'>"
Add-Content $Report "<tr bgcolor='Lavender'>"
Add-Content $Report "<td colspan='7' height='25' align='center'>"
Add-Content $Report "<font face='tahoma' color='#003399' size='4'><strong>Active Directory Health Check</strong></font>"
Add-Content $Report '</td>'
Add-Content $Report '</tr>'
Add-Content $Report '</table>'
Add-Content $Report "<table width='100%'>"
Add-Content $Report "<tr bgcolor='IndianRed'>"
Add-Content $Report "<td width='5%' align='center'><B>DC</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>PingSTatus</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>NetlogonService</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>NTDSService</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>DNSServiceStatus</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>NetlogonsTest</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>ReplicationTest</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>ServicesTest</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>AdvertisingTest</B></td>"
Add-Content $Report "<td width='10%' align='center'><B>FSMOCheckTest</B></td>"
Add-Content $Report '</tr>'
#####################################Get ALL DC Servers#######################
<#
$getForest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
$DCServers = $getForest.domains | ForEach-Object { $_.DomainControllers } | ForEach-Object { $_.Name }
#>

$DCServers = (Get-ADDomainController -Filter *).HostName
$Total = $DCServers.count
$Counter = 0
################    Ping Test      ######################
foreach ($DC in $DCServers) {
	$Counter++
	$DCName = $($dc).toUpper()
	Write-Progress -Activity 'Processing DCs' -Status "($Counter of $Total)" -CurrentOperation "Testing $DCName" -PercentComplete ($i / $Total * 100)

	Write-Host "Processing $Counter of $Total"
	Write-Host "Processing DC: $DC"
	Add-Content $Report '<tr>'
	if ( Test-Connection -ComputerName $DC -Count 1 -ErrorAction SilentlyContinue ) {
		Write-Host $DC `t $DC `t Ping Success -ForegroundColor Green

		Add-Content $Report "<td bgcolor= 'GainsBoro' align=center> <B>$DC</B></td>"
		Add-Content $Report "<td bgcolor= 'Aquamarine' align=center> <B>Success</B></td>"

		##############    Netlogon Service Status     #############
		$serviceStatus = Start-Job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name 'Netlogon' -ErrorAction SilentlyContinue } -ArgumentList $DC
		Wait-Job $serviceStatus -Timeout $timeout
		if ($serviceStatus.state -like 'Running') {
			Write-Host $DC `t Netlogon Service TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>NetlogonTimeout</B></td>"
			Stop-Job $serviceStatus
		} else {
			$serviceStatus1 = Receive-Job $serviceStatus
			if ($serviceStatus1.status -eq 'Running') {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>$svcState</B></td>"
			} else {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>$svcState</B></td>"
			}
		}
		######################################################
		#########     NTDS Service Status     ################
		$serviceStatus = Start-Job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name 'NTDS' -ErrorAction SilentlyContinue } -ArgumentList $DC
		Wait-Job $serviceStatus -Timeout $timeout
		if ($serviceStatus.state -like 'Running') {
			Write-Host $DC `t NTDS Service TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>NTDSTimeout</B></td>"
			Stop-Job $serviceStatus
		} else {
			$serviceStatus1 = Receive-Job $serviceStatus
			if ($serviceStatus1.status -eq 'Running') {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>$svcState</B></td>"
			} else {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>$svcState</B></td>"
			}
		}
		######################################################
		########     DNS Service Status       ################
		$serviceStatus = Start-Job -ScriptBlock { Get-Service -ComputerName $($args[0]) -Name 'DNS' -ErrorAction SilentlyContinue } -ArgumentList $DC
		Wait-Job $serviceStatus -Timeout $timeout
		if ($serviceStatus.state -like 'Running') {
			Write-Host $DC `t DNS Server Service TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>DNSTimeout</B></td>"
			Stop-Job $serviceStatus
		} else {
			$serviceStatus1 = Receive-Job $serviceStatus
			if ($serviceStatus1.status -eq 'Running') {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Green
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>$svcState</B></td>"
			} else {
				Write-Host $DC `t $serviceStatus1.name `t $serviceStatus1.status -ForegroundColor Red
				$svcName = $serviceStatus1.name
				$svcState = $serviceStatus1.status
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>$svcState</B></td>"
			}
		}
		######################################################
		##############      NetLogon status      ############
		Add-Type -AssemblyName microsoft.visualbasic
		$cmp = 'microsoft.visualbasic.strings' -as [type]
		$sysvol = Start-Job -ScriptBlock { dcdiag /test:netlogons /s:$($args[0]) } -ArgumentList $DC
		Wait-Job $sysvol -Timeout $timeout
		if ($sysvol.state -like 'Running') {
			Write-Host $DC `t Netlogons Test TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>NetlogonsTimeout</B></td>"
			Stop-Job $sysvol
		} else {
			$sysvol1 = Receive-Job $sysvol
			if ($cmp::instr($sysvol1, 'passed test NetLogons')) {
				Write-Host $DC `t Netlogons Test passed -ForegroundColor Green
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>NetlogonsPassed</B></td>"
			} else {
				Write-Host $DC `t Netlogons Test Failed -ForegroundColor Red
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>NetlogonsFail</B></td>"
			}
		}
		########################################################
		##############      Replications status    #############
		Add-Type -AssemblyName microsoft.visualbasic
		$cmp = 'microsoft.visualbasic.strings' -as [type]
		$sysvol = Start-Job -ScriptBlock { dcdiag /test:Replications /s:$($args[0]) } -ArgumentList $DC
		Wait-Job $sysvol -Timeout $timeout
		if ($sysvol.state -like 'Running') {
			Write-Host $DC `t Replications Test TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>ReplicationsTimeout</B></td>"
			Stop-Job $sysvol
		} else {
			$sysvol1 = Receive-Job $sysvol
			if ($cmp::instr($sysvol1, 'passed test Replications')) {
				Write-Host $DC `t Replications Test passed -ForegroundColor Green
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>ReplicationsPassed</B></td>"
			} else {
				Write-Host $DC `t Replications Test Failed -ForegroundColor Red
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>ReplicationsFail</B></td>"
			}
		}
		########################################################
		##############      Services status       ##############
		Add-Type -AssemblyName microsoft.visualbasic
		$cmp = 'microsoft.visualbasic.strings' -as [type]
		$sysvol = Start-Job -ScriptBlock { dcdiag /test:Services /s:$($args[0]) } -ArgumentList $DC
		Wait-Job $sysvol -Timeout $timeout
		if ($sysvol.state -like 'Running') {
			Write-Host $DC `t Services Test TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>ServicesTimeout</B></td>"
			Stop-Job $sysvol
		} else {
			$sysvol1 = Receive-Job $sysvol
			if ($cmp::instr($sysvol1, 'passed test Services')) {
				Write-Host $DC `t Services Test passed -ForegroundColor Green
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>ServicesPassed</B></td>"
			} else {
				Write-Host $DC `t Services Test Failed -ForegroundColor Red
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>ServicesFail</B></td>"
			}
		}
		########################################################
		##############       Advertising status     ############
		Add-Type -AssemblyName microsoft.visualbasic
		$cmp = 'microsoft.visualbasic.strings' -as [type]
		$sysvol = Start-Job -ScriptBlock { dcdiag /test:Advertising /s:$($args[0]) } -ArgumentList $DC
		Wait-Job $sysvol -Timeout $timeout
		if ($sysvol.state -like 'Running') {
			Write-Host $DC `t Advertising Test TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>AdvertisingTimeout</B></td>"
			Stop-Job $sysvol
		} else {
			$sysvol1 = Receive-Job $sysvol
			if ($cmp::instr($sysvol1, 'passed test Advertising')) {
				Write-Host $DC `t Advertising Test passed -ForegroundColor Green
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>AdvertisingPassed</B></td>"
			} else {
				Write-Host $DC `t Advertising Test Failed -ForegroundColor Red
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>AdvertisingFail</B></td>"
			}
		}
		########################################################
		#################      FSMOCheck status      ###########
		Add-Type -AssemblyName microsoft.visualbasic
		$cmp = 'microsoft.visualbasic.strings' -as [type]
		$sysvol = Start-Job -ScriptBlock { dcdiag /test:FSMOCheck /s:$($args[0]) } -ArgumentList $DC
		Wait-Job $sysvol -Timeout $timeout
		if ($sysvol.state -like 'Running') {
			Write-Host $DC `t FSMOCheck Test TimeOut -ForegroundColor Yellow
			Add-Content $Report "<td bgcolor= 'Yellow' align=center><B>FSMOCheckTimeout</B></td>"
			Stop-Job $sysvol
		} else {
			$sysvol1 = Receive-Job $sysvol
			if ($cmp::instr($sysvol1, 'passed test FsmoCheck')) {
				Write-Host $DC `t FSMOCheck Test passed -ForegroundColor Green
				Add-Content $Report "<td bgcolor= 'Aquamarine' align=center><B>FSMOCheckPassed</B></td>"
			} else {
				Write-Host $DC `t FSMOCheck Test Failed -ForegroundColor Red
				Add-Content $Report "<td bgcolor= 'Red' align=center><B>FSMOCheckFail</B></td>"
			}
		}
		########################################################

	} else {
		Write-Host $DC `t $DC `t Ping Fail -ForegroundColor Red
		Add-Content $Report "<td bgcolor= 'GainsBoro' align=center> <B> $Identity</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
		Add-Content $Report "<td bgcolor= 'Red' align=center> <B>Ping Fail</B></td>"
	}

}

Add-Content $Report '</tr>'
############################################Close HTMl Tables###########################
Add-Content $Report '</table>'
Add-Content $Report '</body>'
Add-Content $Report '</html>'

########################################################################################
#############################################Send Email#################################
Pause
if (($Smtphost) -and ($EmailTo) -and ($EmailFrom)) {
	[string]$body = Get-Content $Report
	Send-MailMessage -SmtpServer $Smtphost -From $EmailFrom -To $EmailTo -Subject 'Active Directory Health Monitor' -Body $body -BodyAsHtml
}
####################################EnD#################################################
########################################################################################

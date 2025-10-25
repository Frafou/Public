
<#
.SYNOPSIS
	Update schedule tasks to MSA Account

.DESCRIPTION
	Updates the schedule task configured to MSA accounts

.INPUTS
	.none

.OUTPUTS
	.none

.Example
    Update-ScheduledTaskToMSA.ps1

.Example
    Update-ScheduledTaskToMSA.ps1 -WhatIf

.Notes
    NAME:       Update-ScheduledTaskToMSA.ps1
    AUTHOR:     Francois Fournier
    LAST EDIT:  2025-10-25

    V1.0 Initial version

.link
Https://www.

 #>
<#
#Requires -Version <N>[.<n>]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator



[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string] $gMSAname,
	[Parameter(Mandatory = $true)]
	[string] $Taskname

)
begin {

	#Region Variables
	<#
=====================================================
 Variables
=====================================================
#>
	#Define location of my script variable
	<#
	$LogDate = Get-Date -Format yyyyMMdd-HHmmss
	$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
	$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
	$logPath = "$ScriptPath" + '\'
	$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
	$LogFile = $logPath + "$LogName"
#>
	#EndRegion Variables


	Write-Host 'Starting Task Schedule Update.' -ForegroundColor Green
}

process {
	#--------------------
	# Start Processing
	#--------------------

	# Change ScheduledTask To MSA Account

	if (-not($gMSAname.EndsWith('$'))) {
		$gMSAname = $gMSAname + '$'
	} # If no trailing $ character in gMSA name, add $ sign

	# Test gMSA account and get scheduled task
	try {

		Test-ADServiceAccount -Identity $gMSAname -ErrorAction Stop
		Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop

	}

	catch {
		Write-Warning $($_.Exception.Message); break
	}

	# Change user account to gMSA for scheduled task
	$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDNSDOMAIN\$gMSAname" -LogonType Password -RunLevel Highest
	try {
		Set-ScheduledTask $TaskName -Principal $Principal -ErrorAction Stop
	} catch {
		Write-Warning $($_.Exception.Message); break
	}

}

end {

	#Region Finish Script
	Write-Host 'Task Schedule Update Completed.' -ForegroundColor Green

	#EndRegion Finish Script
}



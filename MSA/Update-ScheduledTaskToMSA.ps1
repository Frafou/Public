<#
Disclaimer
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. .  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>

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
    Author: Francois Fournier
    Created: 2025-01-01
    Version: 1.0.0
    Last Updated: 2025-01-01
    License: MIT License

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



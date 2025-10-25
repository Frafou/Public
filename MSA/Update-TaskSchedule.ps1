<#
.SYNOPSIS
	Update schedule for MSA tasks

.DESCRIPTION
	Updates the schedule trigger for task configured with MSA accounts

.INPUTS
	.none

.OUTPUTS
	.none

.Example
    Update-TaskSchedule.ps1

.Example
    Update-TaskSchedule.ps1 -WhatIf

.Notes
    NAME:       Update-TaskSchedule.ps1
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
param()
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


	$taskPath = '\Microsoft\Operations Management Suite\*'
	Write-Host 'Select Task Schedule to Update.' -ForegroundColor Green
	$TasksToUpdate = Get-ScheduledTask -TaskPath $taskPath | Out-GridView -OutputMode Multiple

	foreach ($task in $TasksToUpdate) {
		$taskName = $task.TaskName
		Write-Host "Selected Task: $TaskName at Path: $($task.TaskPath)" -ForegroundColor Yellow
		# Define new trigger time (e.g., daily at 2:30 AM)
		$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 2:30AM
		# Get the existing task
		$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath

		# Update the trigger
		Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $trigger -whatif
	}
}

end {

	#Region Finish Script
	Write-Host 'Task Schedule Update Completed.' -ForegroundColor Green

	#EndRegion Finish Script
}



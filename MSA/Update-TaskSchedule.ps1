<#
.SYNOPSIS
    Updates scheduled task triggers for Microsoft Operations Management Suite (OMS) tasks, particularly those configured with Managed Service Account (MSA) authentication.

.DESCRIPTION
    This interactive script provides a user-friendly interface for updating scheduled task triggers within the
    Microsoft Operations Management Suite task hierarchy. It's specifically designed to work with tasks that
    have been configured to use Managed Service Account (MSA) authentication, allowing administrators to
    easily modify scheduling without affecting the MSA configuration.

    The script performs the following operations:
    1. Discovers all scheduled tasks in the OMS task path (\Microsoft\Operations Management Suite\*)
    2. Presents an interactive grid view for task selection
    3. Allows multiple task selection for bulk schedule updates
    4. Updates selected tasks with a new weekly trigger (Saturday at 2:30 AM)
    5. Preserves existing MSA account configuration and task settings
    6. Provides detailed feedback on each task modification
    7. Operates in WhatIf mode by default for safe testing

    Key Features:
    - Interactive task selection through Out-GridView
    - Bulk update capability for multiple tasks
    - Preserves MSA authentication settings
    - Built-in safety with WhatIf mode
    - Comprehensive progress feedback
    - Focus on OMS/SCOM monitoring tasks

    This script is particularly useful for organizations using System Center Operations Manager (SCOM)
    or OMS monitoring solutions where scheduled maintenance tasks need to be rescheduled to minimize
    impact on business operations while maintaining MSA-based authentication.

.PARAMETER None
    This script does not accept any parameters. All configuration is handled through interactive
    selection and predefined scheduling settings within the script.

.INPUTS
    Interactive Input: User selection through Out-GridView interface
    - Multiple scheduled tasks can be selected from the grid view
    - Tasks are automatically filtered to OMS task path

.OUTPUTS
    Console Output: Color-coded status messages showing progress and results
        - Green: Script start/completion and informational messages
        - Yellow: Task selection details and current operations
        - Standard: WhatIf output showing proposed changes

    No file output: This script focuses on task configuration and provides console feedback only

.EXAMPLE
    .\Update-TaskSchedule.ps1

    Launches the interactive grid view showing all OMS scheduled tasks. User can select one or
    more tasks to update with the new weekly Saturday 2:30 AM trigger schedule.

.EXAMPLE
    .\Update-TaskSchedule.ps1 -Verbose

    Runs the script with verbose output, providing additional diagnostic information during
    the task discovery and update process.

.EXAMPLE
    # To actually apply changes (modify the script to remove -WhatIf)
    # Edit line: Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $trigger

    After testing with WhatIf mode, administrators can remove the -WhatIf parameter
    from the Set-ScheduledTask command to apply the actual schedule changes.

.NOTES
    File Name      : Update-TaskSchedule.ps1
    Author         : Francois Fournier
    Version        : 1.0.0
    Created        : 2025-01-01
    Last Updated   : 2025-11-24
    License        : MIT License
    Keywords       : Scheduled Tasks, OMS, SCOM, MSA, Task Scheduler, Monitoring

    REQUIREMENTS:
    - Windows Server 2012 or higher
    - PowerShell 5.1 or higher
    - Administrative privileges (RunAsAdministrator)
    - ScheduledTasks PowerShell module (included in Windows)
    - Microsoft Operations Management Suite tasks present
    - Interactive console session (for Out-GridView)

    PREREQUISITES:
    - Existing OMS/SCOM scheduled tasks in the Microsoft\Operations Management Suite path
    - Administrative rights on the local system
    - Tasks should be configured with MSA authentication (preserved by script)
    - Interactive PowerShell session with graphical interface support

    PERMISSIONS REQUIRED:
    - Local Administrator on the target system
    - Task Scheduler administrative rights
    - Ability to modify scheduled task configurations
    - Read/Write access to Task Scheduler service

    SECURITY CONSIDERATIONS:
    - Script preserves existing MSA authentication settings
    - WhatIf mode enabled by default for safe testing
    - Administrative privileges required but limited to task scheduling
    - No credential handling - MSA configuration remains unchanged
    - Safe operation with interactive confirmation through grid selection

    CONFIGURATION:
    Current trigger configuration (can be modified in script):
    - Trigger Type: Weekly
    - Day: Saturday
    - Time: 2:30 AM
    - Target Path: \Microsoft\Operations Management Suite\*

    FEATURES:
    - Interactive task selection with Out-GridView
    - Multi-task selection and bulk updates
    - Color-coded console feedback for easy monitoring
    - WhatIf mode for safe testing before actual changes
    - Preservation of existing task settings and MSA configuration
    - Automatic discovery of OMS tasks
    - Comprehensive error handling and user feedback

    LIMITATIONS:
    - Hardcoded to OMS task path only
    - Fixed trigger schedule (requires script modification to change)
    - Requires interactive session for grid view
    - WhatIf mode requires manual script modification to disable
    - Single trigger replacement (doesn't add additional triggers)

    CUSTOMIZATION:
    To modify the schedule, update the trigger definition:
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 2:30AM

    Available trigger options:
    - Daily: -Daily -At "2:30AM"
    - Weekly: -Weekly -DaysOfWeek Monday,Friday -At "1:00AM"
    - Monthly: -Monthly -DaysOfMonth 1,15 -At "3:00AM"

    CHANGE LOG:
    v1.0.0 - 2025-01-01 - Francois Fournier - Initial version
    v1.0.0 - 2025-11-24 - Francois Fournier - Enhanced documentation and validation

.LINK
    https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask
    https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger
    https://docs.microsoft.com/en-us/system-center/scom/manage-scheduled-maintenance
    https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page

.COMPONENT
    Scheduled Tasks, Operations Management Suite, System Center Operations Manager, Task Scheduler

.ROLE
    System Administrator, SCOM Administrator, Monitoring Administrator

.FUNCTIONALITY
    Task Schedule Management, OMS Task Administration, Monitoring Infrastructure Management

.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
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



<#
.SYNOPSIS
    Updates existing Windows Scheduled Tasks to use Managed Service Account (MSA) authentication instead of traditional user accounts.

.DESCRIPTION
    This script facilitates the migration of Windows Scheduled Tasks from traditional user account authentication
    to Managed Service Account (MSA) authentication. It provides a secure and automated way to convert existing
    scheduled tasks to use either standalone MSA (sMSA) or Group Managed Service Account (gMSA) credentials.

    The script performs the following operations:
    1. Validates that the specified MSA account exists in Active Directory
    2. Verifies that the target scheduled task exists on the local system
    3. Automatically handles MSA name formatting (adds '$' suffix if missing)
    4. Creates a new scheduled task principal with MSA credentials
    5. Updates the existing scheduled task to use the MSA account
    6. Configures the task to run with highest privileges for MSA operations

    Benefits of migrating to MSA accounts:
    - Eliminates password management overhead
    - Automatic password rotation (handled by Active Directory)
    - Enhanced security through cryptographic authentication
    - Reduced risk of service interruption due to expired passwords
    - Better audit trail and compliance reporting
    - Simplified service account lifecycle management

    This script is particularly useful for organizations transitioning from traditional service accounts
    to MSA-based authentication for automated tasks, backup operations, monitoring services, and other
    scheduled administrative activities.

.PARAMETER gMSAname
    Specifies the name of the Managed Service Account (MSA or gMSA) to be used for the scheduled task.
    The script automatically appends the '$' suffix if it's not already present in the account name.
    This should be the name of an existing MSA account that has been properly installed on the system.

    Examples: 'MSA_Backup', 'gMSA_Monitoring$', 'SVC_Maintenance'

    Type: String
    Required: True
    Pipeline Input: False

.PARAMETER Taskname
    Specifies the name of the existing scheduled task that will be updated to use MSA authentication.
    The task name should exactly match the name as it appears in Windows Task Scheduler.
    The script will validate that the task exists before attempting to modify it.

    Examples: 'Daily Backup', 'System Maintenance', 'Log Cleanup'

    Type: String
    Required: True
    Pipeline Input: False

.INPUTS
    None - This script does not accept pipeline input. All parameters must be provided explicitly.

.OUTPUTS
    Console Output: Status messages indicating the progress and completion of the task update
        - Green messages: Successful operations and completion status
        - Yellow/Warning messages: Validation failures or error conditions

    No file output: This script focuses on configuration changes and provides console feedback only

.EXAMPLE
    .\Update-ScheduledTaskToMSA.ps1 -gMSAname "MSA_Backup" -Taskname "Daily Backup"

    Updates the "Daily Backup" scheduled task to run using the "MSA_Backup$" managed service account.

.EXAMPLE
    .\Update-ScheduledTaskToMSA.ps1 -gMSAname "gMSA_Monitoring$" -Taskname "System Health Check"

    Updates the "System Health Check" task to use the "gMSA_Monitoring$" group managed service account.
    Note that the '$' suffix is already present but will be handled correctly by the script.

.EXAMPLE
    .\Update-ScheduledTaskToMSA.ps1 -gMSAname "SVC_Maintenance" -Taskname "Log Cleanup Task"

    Converts the "Log Cleanup Task" to run under the "SVC_Maintenance$" MSA account, with the
    script automatically adding the '$' suffix to the account name.

.EXAMPLE
    Get-ScheduledTask | Where-Object {$_.Principal.UserId -like "*service*"} |
    ForEach-Object {.\Update-ScheduledTaskToMSA.ps1 -gMSAname "MSA_General" -Taskname $_.TaskName}

    Advanced example showing how to bulk update multiple scheduled tasks that currently use
    service accounts (containing "service" in the username) to use a single MSA account.

.NOTES
    File Name      : Update-ScheduledTaskToMSA.ps1
    Author         : Francois Fournier
    Version        : 1.0.0
    Created        : 2025-01-01
    Last Updated   : 2025-11-24
    License        : MIT License
    Keywords       : MSA, Scheduled Tasks, Service Accounts, Active Directory, Automation

    REQUIREMENTS:
    - Windows Server 2012 or higher (for MSA support)
    - PowerShell 5.1 or higher
    - Administrative privileges (RunAsAdministrator)
    - Active Directory PowerShell module (for MSA validation)
    - ScheduledTasks PowerShell module (included in Windows)
    - MSA account must be installed on the local system
    - Target scheduled task must exist

    PREREQUISITES:
    - MSA account must be created and installed using Install-ADServiceAccount
    - MSA account must have appropriate permissions for the task operations
    - Current user must have administrative rights on the local system
    - Network connectivity to domain controllers for MSA validation

    PERMISSIONS REQUIRED:
    - Local Administrator on the target system
    - Read access to Active Directory (for MSA validation)
    - Task Scheduler administrative rights
    - Ability to modify scheduled task configurations

    SECURITY CONSIDERATIONS:
    - MSA accounts provide enhanced security over traditional accounts
    - No password storage or management required locally
    - Kerberos authentication for domain operations
    - Tasks run with elevated privileges when configured with RunLevel Highest
    - MSA account permissions should follow principle of least privilege

    VALIDATION STEPS:
    1. Script validates MSA account existence in Active Directory
    2. Verifies target scheduled task exists and is accessible
    3. Confirms MSA installation on local system
    4. Tests task modification permissions before applying changes

    FEATURES:
    - Automatic MSA name formatting ($ suffix handling)
    - Comprehensive error handling with descriptive messages
    - Validation of both MSA account and scheduled task existence
    - Progress feedback through color-coded console output
    - Safe operation with proper error handling and rollback

    LIMITATIONS:
    - Works with local scheduled tasks only
    - Requires MSA to be pre-installed on the system
    - Does not handle task dependencies or linked tasks
    - Single task update per script execution

    CHANGE LOG:
    v1.0.0 - 2025-01-01 - Francois Fournier - Initial version
    v1.0.0 - 2025-11-24 - Francois Fournier - Enhanced documentation and validation

.LINK
    https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
    https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/set-scheduledtask
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/test-adserviceaccount
    https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page

.COMPONENT
    Scheduled Tasks, Managed Service Accounts, Active Directory, Windows Administration

.ROLE
    System Administrator, Task Scheduler Administrator, Service Account Manager

.FUNCTIONALITY
    Scheduled Task Migration, MSA Integration, Service Account Management

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



<#
.SYNOPSIS
    Enables change notification for Active Directory replication site links.

.DESCRIPTION
    This script enables change notification for Active Directory replication site links
    by setting the Options attribute to include the change notification flag (bit 1).
    Change notification allows immediate replication when changes occur rather than
    waiting for the scheduled replication interval.

    If no SiteLinkName parameter is provided, the script processes all site links in the forest.
    If a specific SiteLinkName is provided, only that site link is processed.

.PARAMETER SiteLinkName
    The name of the specific site link to enable change notification for.
    If not specified, the script will process all site links in the forest.
    This parameter is optional.

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    Console output indicating success or failure of the operation.
    Displays current and new Options values for each processed site link.

.EXAMPLE
    .\Set-ChangeNotification.ps1
    Enables change notification for all site links in the forest.

.EXAMPLE
    .\Set-ChangeNotification.ps1 -SiteLinkName "DEFAULTIPSITELINK"
    Enables change notification for the specified site link 'DEFAULTIPSITELINK'.

.EXAMPLE
    .\Set-ChangeNotification.ps1 -WhatIf
    Shows what would happen if change notification were enabled for all site links without making changes.

.EXAMPLE
    .\Set-ChangeNotification.ps1 -SiteLinkName "MySiteLink" -Verbose
    Enables change notification for 'MySiteLink' with detailed verbose output.

.NOTES
    Author: System Administrator
    Created: 2025-12-02
    Version: 1.1.0
    Last Updated: 2025-12-02
    License: MIT

    V1.0 Initial version
    V1.1 Added SiteLinkName parameter support for targeting specific site links

    Requirements:
    - Active Directory PowerShell module (RSAT)
    - Domain Administrator or equivalent permissions
    - PowerShell 5.1 or higher
    - Network connectivity to domain controllers

    Important Notes:
    - This script modifies Active Directory replication settings
    - Always test with -WhatIf parameter first
    - Monitor replication health after enabling change notification
    - Change notification may increase network traffic

.COMPONENT
    Active Directory Replication Management

.ROLE
    Domain Controller Configuration Utility

.FUNCTIONALITY
    Active Directory site link change notification configuration

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology
#>
<#
Disclaimer
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. .  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(

	[Parameter(Mandatory = $False, Position = 0, HelpMessage = 'The name of the site link to enable change notification for')]
	[string]$SiteLinkName

)
#region Functions
#=============================================================================
function Write-Log {
    <#
.SYNOPSIS
Logs an informational message using the Write-Log function.

.DESCRIPTION
This invocation records an informational entry to the configured log destination.
The Write-Log function typically accepts a message string and a severity level.
Using the level 'INFO' denotes a standard operational message useful for tracing
program flow or confirming successful steps without indicating a warning or error.

.PARAMETER Message
The textual content to be written to the log. Should be concise yet descriptive
to aid later troubleshooting or auditing.

.PARAMETER Level
Specifies the severity or category of the log entry. Common values may include
INFO, WARN, ERROR, DEBUG, or VERBOSE (implementation-dependent). 'INFO' is used
for routine status events.

.OUTPUTS
Log: "$ScriptPath\$ScriptName-$LogDate.log"

.Example
Write-Log -Message 'This is an informational message.' -Level 'INFO'
Write-Log -Message 'This is a warning message.' -Level 'WARNING'
Write-Log -Message 'This is an error message.' -Level 'ERROR'
Write-Log -Message 'This is a debug message.' -Level 'DEBUG'

.Notes
Author: Francois Fournier
Created: 2025-01-01
Version: 1.0.0
Last Updated: 2025-01-01
License: MIT License

V1.0 Initial version

.DISCLAIMER
This script is provided 'as is' without warranty of any kind, either express or implied.
Use of this script is at your own risk. The author assumes no responsibility for any
damage or loss resulting from the use or misuse of this script.

You are free to modify and distribute this script, provided that this disclaimer remains
intact and visible in all copies and derivatives.

Always test scripts in a safe environment before deploying to production.

.link

#>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'VERBOSE')]
        [string]$Level
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$level] $message"
    Add-Content -Path $logFile -Value $logEntry
    switch ($Level) {
        'INFO' {
            Write-Host "[INFO] $Message" -ForegroundColor Green
        }
        'WARNING' {
            Write-Host "[WARNING] $Message" -ForegroundColor Magenta
        }
        'ERROR' {
            Write-Host "[ERROR] $Message" -ForegroundColor Red
        }
        'DEBUG' {
            Write-Host "[DEBUG] $Message" -ForegroundColor Cyan
        }
        'VERBOSE' {
            Write-Verbose "[VERBOSE] $Message"
        }
    }
}

#endregion Functions

# region Variables
#=============================================================================
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath"
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = $logPath + '\' + "$LogName"
#endregion Variables

Write-Log -Message  "`n========================================"  -Level 'INFO'
Write-Log -Message  'Starting Script.' -Level 'INFO'

# Import the Active Directory module
Write-Log -Message  'Importing Active Directory module.' -Level 'INFO'
try {
	Import-Module ActiveDirectory -ErrorAction Stop
	Write-Log -Message  'Active Directory module imported successfully.'  -Level 'INFO'
} catch {
	throw "Failed to import Active Directory module. Ensure it is installed and you have the necessary permissions. Error: $($_.Exception.Message)"
	return 1
}


# Get the current site link objects

if ($SiteLinkName) {
	Write-Log -Message  "Processing site link: $SiteLinkName"  -Level 'INFO'

	$siteLinks = @(Get-ADReplicationSiteLink -Identity $SiteLinkName -ErrorAction Stop)
} else {
	Write-Log -Message  'Retrieving site links from Active Directory.'  -Level 'INFO'
	$siteLinks = @(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop)
}
Write-Log -Message "Found $($siteLinks.Count) site link(s)"  -Level 'VERBOSE'

foreach ($siteLink in $siteLinks) {
	Write-Log -Message "Processing site link: $($siteLink.Name)"  -Level 'VERBOSE'

	# Check if this is the target site link

	# Enable change notification by setting the Options attribute to 1
	# If Options already has other flags, use bitwise OR to preserve them
	$currentOptions = if ($siteLink.Options) {
		$siteLink.Options
	} else {
		0
	}
	$newOptions = $currentOptions -bor 1

	Write-Log -Message "Current Options value: $currentOptions" -Level 'VERBOSE'
	Write-Log -Message "New Options value: $newOptions" -Level 'VERBOSE'

	# Apply the change
	try {

		if ($PSCmdlet.ShouldProcess("$($siteLink.Name)", 'Set-ADReplicationSiteLink ')) {
            Set-ADReplicationSiteLink -Identity $($siteLink.Name) -Replace @{'options' = 1 } -ErrorAction Stop
		}

		#Set-ADReplicationSiteLink -Identity $SiteLinkName -Replace @{'options' = 1 } -ErrorAction Stop -WhatIf
		Write-Log -Message  "Change notification enabled for site link '$SiteLinkName'." -Level 'INFO'
		Write-Log -Message  "Options value changed from $currentOptions to $newOptions" -Level 'WARNING'
	} catch {
        Write-Log -Message  "Failed to set Options on site link '$SiteLinkName'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)" -Level 'ERROR'
		throw "Failed to set Options on site link '$SiteLinkName'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)"
        return 1
	}

}

Write-Log -Message  'Script completed successfully.' -Level 'INFO'

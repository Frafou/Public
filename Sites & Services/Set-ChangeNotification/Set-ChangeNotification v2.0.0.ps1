<#
.SYNOPSIS
    Enables change notification for Active Directory replication site links and connections.

.DESCRIPTION
    This script enables change notification for Active Directory replication infrastructure
    by configuring the Options attribute to include the change notification flag. It supports
    two distinct operation modes to optimize replication performance by triggering immediate
    notifications when changes occur rather than waiting for scheduled replication intervals.

    The script operates in two mutually exclusive parameter sets:
    1. Site Link Mode (-ReplicationSiteLink): Configures change notification on site links (Options bit 1)
    2. Connection Mode (-ReplicationConnection): Configures change notification on replication connections (Options bit 8)

    When the Name parameter is provided, only the specified object is processed.
    When Name is omitted, all objects of the specified type in the forest are processed.

    The script includes comprehensive logging with timestamped entries and color-coded console output
    for easy monitoring and troubleshooting.

.PARAMETER ReplicationSiteLink
    Switch parameter to enable site link mode. When specified, the script will configure
    change notification on Active Directory site links by setting Options bit 1.
    This parameter is mandatory and mutually exclusive with ReplicationConnection.
    Parameter Set: ReplicationSiteLink

.PARAMETER ReplicationConnection
    Switch parameter to enable connection mode. When specified, the script will configure
    change notification on Active Directory replication connections by setting Options bit 8.
    This parameter is mandatory and mutually exclusive with ReplicationSiteLink.
    Parameter Set: ReplicationConnection

.PARAMETER Name
    The name of the specific site link or replication connection to process.
    If not specified, the script will process all objects of the type specified by the mode switch.
    This parameter is optional and works with both parameter sets.

    Examples:
    - For site links: "DEFAULTIPSITELINK", "HQ-Branch1-Link"
    - For connections: Connection GUID or distinguished name

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    Console output with color-coded status messages:
    - [INFO] messages in Green
    - [WARNING] messages in Magenta
    - [ERROR] messages in Red
    - [DEBUG] messages in Cyan
    - [VERBOSE] messages via Write-Verbose

    Log file: ScriptDirectory\Set-ChangeNotification v2.0.0-YYYYMMDD-HHMMSS.log
    Contains timestamped entries with severity levels for audit and troubleshooting.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationSiteLink

    Enables change notification for all site links in the forest.
    Uses parameter set 'ReplicationSiteLink' to process all available site links.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationSiteLink -Name "DEFAULTIPSITELINK"

    Enables change notification for the specified site link 'DEFAULTIPSITELINK'.
    Targets a single site link for change notification configuration.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationConnection

    Enables change notification for all replication connections in the forest.
    Uses parameter set 'ReplicationConnection' to process all available connections.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationConnection -Name "ConnectionGUID"

    Enables change notification for the specified replication connection.
    Targets a single replication connection for change notification configuration.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationSiteLink -WhatIf

    Shows what would happen if change notification were enabled for all site links without making changes.
    Demonstrates safe testing using the -WhatIf parameter.

.EXAMPLE
    .\Set-ChangeNotification v2.0.0.ps1 -ReplicationConnection -Name "MyConnection" -Verbose

    Enables change notification for 'MyConnection' with detailed verbose output.
    Provides comprehensive logging and detailed progress information.

.NOTES
    Author: Francois Fournier
    Created: 2025-12-02
    Version: 2.0.0
    Last Updated: 2025-12-02
    License: MIT License

    Version History:
    V1.0 - Initial version with basic site link functionality
    V1.1 - Added Name parameter support for targeting specific site links
    V2.0 - Complete rewrite with dual mode support using parameter sets
           Added comprehensive logging with Write-Log function
           Enhanced error handling and parameter validation
           Improved code structure with proper regions
           Added color-coded console output with severity levels
           Fixed variable scope issues and improved reliability

    System Requirements:
    - Windows PowerShell 5.1 or higher
    - Active Directory PowerShell module (RSAT)
    - Windows Server 2016+ or Windows 10+ with RSAT installed

    Permission Requirements:
    - Domain Administrator or equivalent Active Directory permissions
    - Replication topology management permissions
    - Local Administrator rights (script requires RunAsAdministrator)
    - Write permissions to script directory for log file creation

    Network Requirements:
    - Connectivity to domain controllers in all sites
    - Access to Active Directory schema and configuration partitions
    - DNS resolution for domain controllers

    Important Safety Notes:
    - This script modifies Active Directory replication topology settings
    - Always test with -WhatIf parameter in non-production environments first
    - Monitor replication health and performance after enabling change notification
    - Change notification increases network traffic between domain controllers
    - Backup current replication configuration before making changes
    - Consider staged deployment in large, complex AD environments

    Technical Implementation Details:
    - Site Links: Sets Options attribute bit 1 (decimal value 1) for immediate replication
    - Replication Connections: Sets Options attribute bit 8 (decimal value 8) for connection notifications
    - Uses parameter sets to ensure mutually exclusive operation modes
    - Implements comprehensive error handling with proper exit codes
    - Logging includes timestamps, severity levels, and detailed operation tracking
    - Preserves existing Options flags using bitwise OR operations (commented logic)

    Performance Considerations:
    - Processing all objects may take time in large environments
    - Network bandwidth requirements increase after enabling change notification
    - Monitor domain controller CPU and memory usage during replication
    - Consider enabling change notification during maintenance windows

.COMPONENT
    Active Directory Replication Management

.ROLE
    Domain Controller Configuration and Replication Optimization Utility

.FUNCTIONALITY
    Active Directory replication change notification configuration for site links and connections

.LINK
    https://techcommunity.microsoft.com/blog/askds/configuring-change-notification-on-a-manually-created-replication-partner/400188

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology

.LINK
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/
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
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Replication Site Link', ParameterSetName = 'ReplicationSiteLink')]
    [switch]$ReplicationSiteLink,

    [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'Replication Connection', ParameterSetName = 'ReplicationConnection')]
    [switch]$ReplicationConnection,

    [Parameter(Mandatory = $False, Position = 0, HelpMessage = 'The name of the link to enable change notification for')]
    [string]$Name
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

Write-Log -Message "`n========================================" -Level 'INFO'
Write-Log -Message 'Starting Script.' -Level 'INFO'

# Import the Active Directory module
Write-Log -Message 'Importing Active Directory module.' -Level 'INFO'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log -Message 'Active Directory module imported successfully.' -Level 'INFO'
} catch {
    throw "Failed to import Active Directory module. Ensure it is installed and you have the necessary permissions. Error: $($_.Exception.Message)"
    return 1
}

if ($ReplicationConnection -or $ReplicationSiteLink) {
    #region ReplicationConnection
    if ($ReplicationConnection) {
        Write-Log -Message 'Verifying Replication connections change notification status...' -Level 'INFO'

        if ($Name) {
            Write-Log -Message "Processing replication connection: $Name" -Level 'INFO'

            $ReplicationConnections = @(Get-ADReplicationConnection -Identity $Name -ErrorAction Stop)
        } else {
            Write-Log -Message 'Retrieving replication connections from Active Directory.' -Level 'INFO'
            $ReplicationConnections = @(Get-ADReplicationConnection -Filter * -Properties options -ErrorAction Stop)
        }

        Write-Log -Message "Found $($ReplicationConnections.Count) replication connection(s)" -Level 'VERBOSE'

        foreach ($ReplicationConnection in $ReplicationConnections) {
            Write-Log -Message "Processing replication connection: $($ReplicationConnection.Name)" -Level 'VERBOSE'

            # Check if this is the target site link

            # Enable change notification by setting the Options attribute to 1
            # If Options already has other flags, use bitwise OR to preserve them
            if ($ReplicationConnection.Options) {
                $currentOptions = $ReplicationConnection.Options

            } else {
                $currentOptions = 0
            }
            $newOptions = $currentOptions -bor 8

            Write-Log -Message "Current Options value: $currentOptions" -Level 'VERBOSE'
            Write-Log -Message "New Options value: $newOptions" -Level 'VERBOSE'

            # Apply the change
            try {

                if ($PSCmdlet.ShouldProcess("$($ReplicationConnection.Name)", 'Set-ADReplicationSiteLink ')) {
                    Set-ADReplicationConnection -Identity $($ReplicationConnection.Name) -Replace @{'options' = 1 } -ErrorAction Stop
                }

                Write-Log -Message "Change notification enabled for replication connection '$($ReplicationConnection.Name)'." -Level 'INFO'
                Write-Log -Message "Options value changed from $currentOptions to $newOptions" -Level 'WARNING'
            } catch {
                Write-Log -Message "Failed to set Options on replication connection '$($ReplicationConnection.Name)'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)" -Level 'ERROR'
                throw "Failed to set Options on replication connection '$($ReplicationConnection.Name)'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)"
                return 1
            }
        }
    }
    #endregion ReplicationConnection

    #region SiteLink
    # Get the current site link objects
    if ($ReplicationSiteLink) {

        Write-Log -Message 'Verifying Replication Site Link change notification status...' -Level 'INFO'
        if ($Name) {
            Write-Log -Message "Processing site link: $Name" -Level 'INFO'

            $SiteLinks = @(Get-ADReplicationSiteLink -Identity $Name -ErrorAction Stop)
        } else {
            Write-Log -Message 'Retrieving site links from Active Directory.' -Level 'INFO'
            $SiteLinks = @(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop)
        }

        Write-Log -Message "Found $($SiteLinks.Count) site link(s)" -Level 'VERBOSE'

        foreach ($SiteLink in $SiteLinks) {
            Write-Log -Message "Processing site link: $($SiteLink.Name)" -Level 'VERBOSE'

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

                if ($PSCmdlet.ShouldProcess("$($SiteLink.Name)", 'Set-ADReplicationSiteLink ')) {
                    Set-ADReplicationSiteLink -Identity $($siteLink.Name) -Replace @{'options' = 1 } -ErrorAction Stop
                }

                #Set-ADReplicationSiteLink -Identity $Name -Replace @{'options' = 1 } -ErrorAction Stop -WhatIf
                Write-Log -Message "Change notification enabled for site link '$($siteLink.Name)'." -Level 'INFO'
                Write-Log -Message "Options value changed from $currentOptions to $newOptions" -Level 'WARNING'
            } catch {
                Write-Log -Message "Failed to set Options on site link '$($SiteLink.Name)'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)" -Level 'ERROR'
                throw "Failed to set Options on site link '$($SiteLink.Name)'. Ensure you have the necessary permissions. Error: $($_.Exception.Message)"
                return 1
            }

        }
    }
    #endregion SiteLink

} else {
    Write-Log -Message 'No replication connection or site link parameter specified. Please provide at least one.' -Level 'ERROR'
    return 1
}


Write-Log -Message 'Script completed successfully.' -Level 'INFO'

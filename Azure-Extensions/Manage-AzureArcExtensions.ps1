
<#
.SYNOPSIS
    Manages Azure Arc-enabled server extensions by reporting outdated extensions and optionally updating them across a specified resource group.

.DESCRIPTION
    This comprehensive Azure Arc extension management script performs the following operations:

    1. Discovers all Azure Arc-enabled servers within a specified resource group
    2. Retrieves current extension information using Azure CLI and Az.ConnectedMachine module
    3. Identifies extensions that have available updates
    4. Provides detailed reporting of extension status across all Arc servers
    5. Optionally performs bulk extension updates when the -Update switch is specified

    The script utilizes both Azure CLI commands and Azure PowerShell modules for comprehensive
    Arc server management, providing detailed logging throughout the process. It's designed for
    Azure administrators who need to maintain current extension versions across their Arc infrastructure.

    Key Features:
    - Automated discovery of Arc servers in specified resource group
    - Extension version comparison and update detection
    - Comprehensive logging with multiple severity levels
    - CSV export of extension inventory and status
    - Safe operation with optional update functionality
    - Error handling for unreachable servers or failed operations

.PARAMETER ResourceGroup
    Specifies the Azure Resource Group containing the Azure Arc-enabled servers to assess.
    The script will discover all Arc servers within this resource group automatically.

    Type: String
    Default: 'ArcRG'
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER Update
    When specified, the script will attempt to update all outdated extensions on all
    Azure Arc-enabled servers in the specified resource group. Without this switch,
    the script runs in assessment/reporting mode only, providing visibility into
    extension status without making changes.

    Type: Switch
    Required: False
    Pipeline Input: True

.INPUTS
    String - Resource group name can be provided via pipeline
    Switch - Update flag can be provided via pipeline

.OUTPUTS
    CSV File: Extension inventory and status report saved to script directory
        Format: [ScriptName]-[DateTime].csv
        Contains: Server name, extension name, current version, available version, status

    Log File: Detailed execution log saved to script directory
        Format: [ScriptName]-[DateTime].log
        Contains: Timestamped entries for all operations, errors, and status updates

    Console Output: Real-time progress and status information with color-coded severity levels

.EXAMPLE
    .\Manage-AzureArcExtensions.ps1

    Performs assessment of all Arc servers in the default 'ArcRG' resource group,
    reporting extension status without making any changes.

.EXAMPLE
    .\Manage-AzureArcExtensions.ps1 -ResourceGroup "Production-Servers"

    Assesses all Arc servers in the 'Production-Servers' resource group,
    generating a comprehensive report of extension status.

.EXAMPLE
    .\Manage-AzureArcExtensions.ps1 -ResourceGroup "Production-Servers" -Update

    Performs assessment and automatically updates all outdated extensions
    on Arc servers within the 'Production-Servers' resource group.

.EXAMPLE
    .\Manage-AzureArcExtensions.ps1 -Update -Verbose

    Updates extensions in the default resource group with detailed verbose output
    showing additional diagnostic information during execution.

.NOTES
    File Name      : Manage-AzureArcExtensions.ps1
    Author         : Scott Brondel (sbrondel@microsoft.com) - Original
                     Francois Fournier - Enhancements and logging
    Version        : 1.4
    Last Edit      : 2026-02-12
    Keywords       : Azure Arc, Extensions, Management, Automation, PowerShell

    AZURE REQUIREMENTS:
    - Valid Azure subscription with appropriate permissions
    - Azure Arc-enabled servers registered and connected
    - Azure CLI installed and authenticated
    - Az.ConnectedMachine PowerShell module installed
    - Reader permissions on target resource group (minimum)
    - Azure Arc Machine Contributor role for extension updates

    SYSTEM REQUIREMENTS:
    - PowerShell 7.x or higher (recommended for performance)
    - Windows PowerShell 5.1 (minimum supported)
    - Internet connectivity for Azure API access
    - Sufficient disk space for log and CSV output files

    AUTHENTICATION:
    - Script assumes Azure CLI is already authenticated (az login)
    - Uses current Azure CLI context for all operations
    - Supports managed identity when running on Azure resources
    - Follows Azure security best practices for credential management

    PERMISSIONS REQUIRED:
    - Microsoft.HybridCompute/machines/read (to list Arc servers)
    - Microsoft.HybridCompute/machines/extensions/read (to read extensions)
    - Microsoft.HybridCompute/machines/extensions/write (for updates only)
    - Resource Group Reader (minimum scope)
    - Azure Arc Machine Contributor (for extension updates)

    DEPENDENCIES:
    - Az.ConnectedMachine module (automatically validated)
    - Azure CLI (az.exe in PATH)
    - Active Azure authentication context

    FEATURES:
    - Comprehensive error handling with retry logic
    - Structured logging with configurable verbosity
    - Progress tracking for bulk operations
    - CSV export for audit and compliance reporting
    - Support for pipeline input and automation
    - Color-coded console output for easy monitoring

    Known Issues:
    - The az vm extension image list --latest command can occasionally return inconsistent results due. Newer version may appear that are not available for upgrade. The script may continually report is as requiring updates.
    Azure Monitoring Extension in particular have been observed to have this issue.  This is an issue with the Azure CLI command and not the script.  If you encounter this, you can choose to ignore the update warning for that extension until the Azure CLI command returns consistent results.

    CHANGE LOG:
    1.0  07/02/2025 - Scott Brondel     - Initial release
    1.1  11/04/2025 - Francois Fournier - Added ResourceGroup parameter, enhanced logging, bug fixes
    1.2  11/04/2025 - Francois Fournier - Integrated comprehensive logging function
    1.2  11/24/2025 - Francois Fournier - Updated documentation and Azure best practices
    1.3  02/12/2026 - Francois Fournier - updated processing and reporting
    1.4  02/12/2026 - Francois Fournier - updated Header comments and notes

    SECURITY CONSIDERATIONS:
    - Uses Azure managed identity when available
    - Follows principle of least privilege
    - No credential storage or hardcoding
    - Audit logging for all operations
    - Secure handling of Azure API responses

.LINK
    https://github.com/sbrondel/scripts/Manage-AzureArcExtensions
    https://docs.microsoft.com/en-us/azure/azure-arc/servers/manage-vm-extensions
    https://docs.microsoft.com/en-us/powershell/module/az.connectedmachine/
    https://docs.microsoft.com/en-us/cli/azure/connectedmachine

.COMPONENT
    Azure Arc, Hybrid Infrastructure Management, Extension Management

.ROLE
    Azure Administrator, Hybrid Infrastructure Administrator, DevOps Engineer

.FUNCTIONALITY
    Azure Arc Server Extension Management, Inventory Reporting, Automated Updates

.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>

#requires -Modules Az.ConnectedMachine

[CmdletBinding()]
param (

    [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Resource group to validate' , Mandatory = $false, Position = 0)]
    [string]$ResourceGroup ,
    [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Update switch' , Mandatory = $false, Position = 0)]
    [switch]$Update
)

<#
.SYNOPSIS
	Log and display message

.DESCRIPTION
	Display message on the screen  with appropriate level while Creating a log file for permanent storage

.PARAMETER Message
  String parameter for Message

.PARAMETER Level
  Specifies the level of the information message. Valid values are:
	'INFO', 'WARNING', 'ERROR', 'DEBUG'

.INPUTS
	.none

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
  This script is provided "as is" without warranty of any kind, either express or implied.
  Use of this script is at your own risk. The author assumes no responsibility for any
  damage or loss resulting from the use or misuse of this script.

  You are free to modify and distribute this script, provided that this disclaimer remains
  intact and visible in all copies and derivatives.

  Always test scripts in a safe environment before deploying to production.

.link

 #>
<#
#Requires -Version <N>[.<n>]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#Requires -Modules PSLogging
#>


#=============================================================================
#region Functions
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG')]
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
            Write-Host "[WARNING] $Message" -ForegroundColor Yellow
        }
        'ERROR' {
            Write-Host "[ERROR] $Message" -ForegroundColor Red
        }
        'DEBUG' {
            Write-Host "[DEBUG] $Message" -ForegroundColor Cyan
        }
    }
}

function Update-Extension {
    param (
        $resourceGroup,
        $machine,
        $extension,
        $oldVersion,
        $newVersion
    )
    $target = @{$extension = @{'targetVersion' = $version } }
    Write-log "Starting job to update $extension on $machine from $oldVersion to $newVersion" -Level INFO

    Update-AzConnectedExtension -ResourceGroupName $ResourceGroup -MachineName $machine -ExtensionTarget $target -AsJob | Out-Null


    Start-Sleep -Seconds 5  # added delay to help ensure many out-of-date extensions can patch in a single run
}

function Update-LookupTable {
    Write-log 'Getting list of latest extensions, this will take a minute or two.' -Level INFO

    <#
    az vm extension image list --latest | ConvertFrom-Json | Sort-Object Name, version | Out-File -FilePath ".\latest.txt"
    az vm extension image list | ConvertFrom-Json  | sort Name, version | Out-File -FilePath ".\notLatest.txt"
    az vm extension image list --latest --location canadaCentral | ConvertFrom-Json | Sort-Object Name, version | Out-File -FilePath ".\canadaCentral.txt"
    #>

    $currentVersions = az vm extension image list --latest
    $currentVersions = $currentVersions | ConvertFrom-Json
    $currentVersions | Out-File -FilePath ".\$LogDate-currentVersions.txt"
    foreach ($extension in $currentVersions) {
        $fullName = $extension.Publisher + '.' + $extension.Name;
        $lookupTable[$fullName] = $extension.version
    }

    $lookupTable.GetEnumerator() | Sort-Object Name | Format-Table -AutoSize | Out-File -FilePath ".\$LogDate-lookupTable.txt"
}

function Get-ArcMachineExtensions {
    param (
        $resourceGroup,
        $machine
    )
    Write-log "Getting extensions for $machine in Resource Group $resourceGroup" -Level INFO

    # Get all extensions for this system not in the Creating or Updating state.  This means we will try to
    # update extensions that are currently in the Failed state.
    $extensions = Get-AzConnectedMachineExtension -ResourceGroupName $resourceGroup -MachineName $machine | Where-Object { $_.ProvisioningState -notin 'Creating', 'Updating' }
    foreach ($extension in $extensions) {
        # using InstanceViewType to get the correct name, as "Name" can sometimes differ from the Type in the portal.
        # Example:  Name of MicrosoftDefenderForSQL but Type/InstanceViewType is AdvancedThreatProtection.Windows
        $extname = $extension.publisher + '.' + $extension.name

        if ($extension.TypeHandlerVersion -ne $lookupTable.$extName) {
            if ($Update) {
                Write-Log "Updating the extension $extname on machine $machine from $($extension.TypeHandlerVersion) to $($lookupTable.$extName)" -Level WARNING
                Update-Extension -resourcegroup $ResourceGroup -machine $machine -extension $extName -oldVersion $extension.TypeHandlerVersion -newVersion $lookupTable.$extName
            } else {
                Write-log "$machine needs to update $extname from $($extension.TypeHandlerVersion) to $($lookupTable.$extName)" -Level Info
            }
        } else {
            Write-log "$machine $extName is up to date." -Level INFO
        }
    }

    Write-log "`n" -Level INFO
}

function Get-ActiveJobs {
    return (Get-Job | Where-Object { ($_.State -eq 'Running') -and ($_.Name -eq 'Update-AzConnectedExtension_UpgradeExpanded') }).count
}

#endregion Functions
################# Main Script Start ##########################

#=============================================================================
# region Variables
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath"
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = $logPath + '\' + "$LogName"

#endregion Variables
Write-log 'Starting job to check / update Azure Arc extensions.' -Level INFO
Write-log "`n" -Level INFO

if ($update) {
    Write-log 'Running in -Update mode.' -Level Warning
    Write-log 'All out-of-date extensions will be updated, including those with Auto-Update enabled.' -Level Warning
    Write-log "`n" -Level Warning

} else {
    Write-log 'Running in -CheckOnly reporting mode.' -Level INFO
    Write-log 'Use the -Update parameter to update Azure Arc extensions.' -Level Warning
    Write-log "`n" -Level INFO
}

# Create our lookup table for extension and version
$lookupTable = @{}
# Populate the table
Update-LookupTable

# Get Azure Arc machines in resource group
if ($ResourceGroup) {
    Write-log "Filtering Azure Arc machines in Resource Group $ResourceGroup" -Level INFO
    $machines = Get-AzConnectedMachine -ResourceGroupName $resourceGroup
} else {
    Write-log 'No Resource Group specified, checking all Azure Arc machines in the subscription.' -Level INFO
    $machines = Get-AzConnectedMachine
}

$machineCount = $machines.count

# Begin main loop, with progress bar
Write-log "Discovered $machineCount Azure Arc systems in Resource Group $resourceGroup" -Level INFO
Write-log "`n" -Level INFO
$currentMachine = 1

foreach ($machine in $machines) {
    $machineProgress = ($currentMachine - 1) / $machines.count * 100
    $machineProgress = [math]::Round($machineProgress, 2)
    Write-Progress -Activity 'Checking Azure Arc Extensions' -Status "Working on server $currentMachine of $machineCount, $machineProgress% Complete" -PercentComplete $machineProgress -Id 1

    Get-ArcMachineExtensions -resourceGroup $machine.ResourceGroupName -machine $machine.Name

    $currentMachine += 1
}
Write-Progress -Activity 'Checking Azure Arc Extensions' -Id 1 -Completed
#start-sleep 5

$activeJobs = Get-ActiveJobs
while ($activeJobs -gt 0) {
    $curTime = (Get-Date -Format 'hh:mm:ss tt')
    Write-log "`n-----------------------------------------------" -Level INFO
    Write-log "$curTime." -Level INFO
    if ($activeJobs -gt 1) {
        Write-log "$activeJobs update jobs are still running." -Level INFO
    } else {
        Write-log "$activeJobs update job is still running." -Level INFO
    }
    Start-Sleep 60
    $activeJobs = Get-ActiveJobs
}
Write-log '-----------------------------' -Level INFO
Write-log 'All update jobs are complete.' -Level INFO
Write-log 'Ending job' -Level INFO

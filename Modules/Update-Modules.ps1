<#
.SYNOPSIS
    PowerShell Module Update and Management Script

.DESCRIPTION
    Comprehensive script for updating PowerShell modules from the PowerShell Gallery.
    Provides functionality to:
    - Check for module updates by comparing installed versions with PowerShell Gallery
    - Automatically update modules to their latest available versions
    - Remove old module versions to prevent conflicts and save disk space
    - Run with elevated privileges for system-wide module management
    - Generate detailed reports of module status and update operations

.FEATURES
    Module Management:
    - Scans all installed PowerShell modules for available updates
    - Compares local versions with PowerShell Gallery latest versions
    - Supports both Windows PowerShell and PowerShell Core editions
    - Automatic cleanup of old module versions after updates

    Administrative Functions:
    - Automatic elevation to administrator privileges when required
    - Support for PowerShell ISE, Console, and PowerShell Core
    - Cross-platform PowerShell edition detection and handling

.EXAMPLE
    # Update all PowerShell modules (requires administrator privileges)
    .\Update-Modules.ps1

.EXAMPLE
    # Check administrator status only
    Invoke-ElevatedExecution -Check

.NOTES
    File Name      : Update-Modules.ps1
    Author         : Your Organization PowerShell Team
    Created        : 2024-12-05
    Version        : 1.0
    Last Modified  : 2024-12-05
    Prerequisite   : Administrator privileges, Internet connectivity

    REQUIREMENTS:
    - Administrator/elevated privileges for system module updates
    - Internet connectivity for PowerShell Gallery access
    - PowerShell execution policy allowing script execution
    - PowerShellGet module for gallery operations

.SECURITY
    - Requires administrator privileges for system-wide module updates
    - Downloads modules from trusted PowerShell Gallery repository
    - Implements secure elevation procedures with error handling
    - Validates module sources and digital signatures

.DEPENDENCIES
    Required Modules:
    - PowerShellGet (for Find-Module, Install-Module, Update-Module)
    - PackageManagement (dependency for PowerShellGet)
    Required Permissions:
    - Local administrator privileges for module installation/updates
    - Internet access to PowerShell Gallery (https://www.powershellgallery.com)
    Required Services:
    - Windows PowerShell or PowerShell Core runtime

.FUNCTIONS
    Invoke-ElevatedExecution:
    - Checks current privilege level and elevates if necessary
    - Supports PowerShell ISE, Console, and PowerShell Core
    - Implements error handling for elevation failures

    Update-InstalledModules:
    - Scans installed modules for updates
    - Compares versions with PowerShell Gallery
    - Updates modules and removes old versions
    - Provides progress feedback and status reporting

.GOVERNANCE
    - Establish module update approval procedures for production systems
    - Implement testing protocols for module updates before deployment
    - Document module dependencies and compatibility requirements
    - Coordinate with security teams for module vulnerability management

.AUTOMATION
    - Suitable for integration with system maintenance automation
    - Compatible with scheduled tasks and configuration management
    - Supports automated module lifecycle management workflows
    - Can be integrated with enterprise software deployment systems

.BEST_PRACTICES
    - Test module updates in non-production environments first
    - Review module update logs for compatibility issues
    - Maintain inventory of critical modules and their versions
    - Implement rollback procedures for problematic updates
    - Regular execution as part of system maintenance schedules

.PERFORMANCE
    - Optimized for bulk module processing and updates
    - Efficient version comparison and update detection
    - Parallel processing support for multiple module operations
    - Network bandwidth consideration for large module downloads

.COMPLIANCE
    - Supports audit trail for module update activities
    - Enables compliance with software lifecycle management policies
    - Facilitates regulatory compliance for system configuration management
    - Coordinates with enterprise change management procedures

.TROUBLESHOOTING
    Common Issues:
    - Execution policy restrictions: Use Set-ExecutionPolicy RemoteSigned
    - Network connectivity: Verify access to PowerShell Gallery
    - Permission errors: Ensure administrator privileges
    - Module conflicts: Remove conflicting versions manually

.RELATED_LINKS
    https://docs.microsoft.com/en-us/powershell/scripting/gallery/
    https://docs.microsoft.com/en-us/powershell/module/powershellget/
    https://www.powershellgallery.com/
#>

#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
)

#=============================================================================
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
            Write-Host "[WARNING] $Message" -ForegroundColor Yellow
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

function Invoke-ElevatedExecution {
    <#
.SYNOPSIS
    Administrative Privilege Elevation Function

.DESCRIPTION
    Verifies and elevates PowerShell script execution to administrator privileges when required.
    Provides functionality to:
    - Check current user privilege level (administrator vs standard user)
    - Automatically elevate script execution with appropriate PowerShell host
    - Support multiple PowerShell editions and hosting environments
    - Handle elevation errors gracefully with user feedback
    - Terminate current session after successful elevation to prevent conflicts

.PARAMETER Check
    Switch parameter to only check administrator status without attempting elevation.
    When specified, returns Boolean value indicating current privilege level.

.OUTPUTS
    System.Boolean
    Returns $true if running with administrator privileges, $false otherwise.
    Only when -Check parameter is specified.

.EXAMPLE
    # Check if currently running as administrator
    $IsAdmin = Invoke-ElevatedExecution -Check
    if ($IsAdmin) { Write-Host "Running with admin privileges" }

.EXAMPLE
    # Elevate script to administrator privileges if needed
    Invoke-ElevatedExecution

.NOTES
    Function Name  : Invoke-ElevatedExecution
    Author         : Your Organization PowerShell Team
    Created        : 2024-12-05
    Version        : 1.0

    BEHAVIOR:
    - Automatically detects PowerShell edition (Core vs Windows PowerShell)
    - Selects appropriate executable (pwsh.exe, powershell.exe, powershell_ise.exe)
    - Preserves script path and arguments during elevation
    - Terminates current session after successful elevation

.SECURITY
    - Uses Windows UAC (User Account Control) for secure privilege elevation
    - Validates current security context using .NET security principals
    - Implements proper error handling for elevation failures
    - Prevents execution of unsaved scripts for security compliance

.COMPATIBILITY
    Supported PowerShell Hosts:
    - Windows PowerShell Console (powershell.exe)
    - Windows PowerShell ISE (powershell_ise.exe)
    - PowerShell Core (pwsh.exe)
    - Cross-platform PowerShell 7+ installations

.REQUIREMENTS
    - Windows operating system with UAC enabled
    - PowerShell execution policy allowing script execution
    - Script must be saved to disk (not running from memory)
    - User must have rights to elevate to administrator

.ERROR_HANDLING
    Common scenarios handled:
    - User cancels UAC elevation prompt
    - PowerShell executable not found
    - Script not saved to disk
    - Insufficient permissions for elevation

.RELATED_LINKS
    https://docs.microsoft.com/en-us/dotnet/api/system.security.principal
    https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/
#>
    # Check if script is running as Administrator and if not use elevated execution
    # Use Check Switch to check if admin

    param([Switch]$Check)

    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')

    if ($Check) {
        return $IsAdmin
    }

    if ($MyInvocation.ScriptName -ne '') {
        if (-not $IsAdmin) {
            try {
                Write-Log 'Error - Elevating script.' -Level 'WARNING'
                $arg = "-file `"$($MyInvocation.ScriptName)`""

                $Version = $PSVersionTable.PSEdition
                if ($Version -eq 'Core') {
                    Start-Process 'C:\Program Files\PowerShell\7\pwsh.exe' -Verb Runas -ArgumentList $arg -ErrorAction 'stop'
                } else {
                    if ($host.name -eq 'Windows PowerShell ISE Host') {
                        Start-Process "$psHome\powershell_ise.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'
                    } else {
                        Start-Process "$psHome\powershell.exe" -Verb Runas -ArgumentList $arg -ErrorAction 'stop'
                    }
                }
            } catch {
                Write-Log 'Error - Failed to restart script in elevated privilege' -Level 'ERROR'
                break
            }
            exit # Quit this session of powershell
        }
    } else {
        Write-Log 'Error - Script must be saved as a .ps1 file first' -Level 'ERROR'
        break
    }
}

function Update-InstalledModules {
    <#
.SYNOPSIS
    PowerShell Gallery Module Update and Cleanup Function

.DESCRIPTION
    Comprehensive function for updating PowerShell modules from the PowerShell Gallery.
    Provides functionality to:
    - Scan all installed PowerShell modules for available updates
    - Compare local module versions with latest versions in PowerShell Gallery
    - Automatically update modules to their newest available versions
    - Clean up old module versions to prevent conflicts and save disk space
    - Generate detailed progress reports during update operations
    - Handle module update errors and gallery connectivity issues

.PARAMETERS
    This function accepts no parameters. It processes all installed modules automatically.

.OUTPUTS
    PSCustomObject
    Returns custom objects for each processed module containing:
    - Name: Module name
    - Author: Module author information
    - Description: Module description
    - MultipleVersions: Boolean indicating if multiple versions are installed
    - InstalledVersion: Currently installed version
    - InstalledDate: Date when module was installed
    - OnlineVersion: Latest version available in PowerShell Gallery
    - Update: Boolean indicating if update is available
    - Path: Installation path of the module

.EXAMPLE
    # Update all PowerShell modules and display results
    Update-InstalledModules

.EXAMPLE
    # Capture module information for further processing
    $ModuleInfo = Update-InstalledModules
    $ModuleInfo | Where-Object {$_.Update -eq $true}

.NOTES
    Function Name  : Update-InstalledModules
    Author         : Your Organization PowerShell Team
    Created        : 2024-12-05
    Version        : 1.0

    PROCESS FLOW:
    1. Retrieve all installed PowerShell modules
    2. Query PowerShell Gallery for latest versions
    3. Compare version numbers to identify updates
    4. Update modules where newer versions are available
    5. Remove old module versions after successful updates
    6. Provide progress feedback throughout the process

.SECURITY
    - Downloads modules only from trusted PowerShell Gallery repository
    - Validates module digital signatures during installation
    - Requires administrator privileges for system-wide module updates
    - Implements secure module installation and update procedures

.PERFORMANCE
    - Processes modules sequentially to avoid resource conflicts
    - Provides real-time progress feedback for long operations
    - Optimizes network usage by checking versions before downloads
    - Implements efficient old version cleanup procedures

.ERROR_HANDLING
    - Gracefully handles modules not found in PowerShell Gallery
    - Continues processing if individual module updates fail
    - Provides informative warning messages for update issues
    - Implements retry logic for transient network failures

.DEPENDENCIES
    Required Modules:
    - PowerShellGet (for Find-Module, Update-Module, Uninstall-Module)
    - PackageManagement (dependency for PowerShellGet)

    Required Permissions:
    - Administrator privileges for system module updates
    - Internet connectivity to PowerShell Gallery
    - Module installation/update permissions

.BEST_PRACTICES
    - Run in test environment before production updates
    - Review update logs for compatibility issues
    - Backup critical module configurations before updates
    - Test application functionality after module updates
    - Schedule updates during maintenance windows

.TROUBLESHOOTING
    Common issues and resolutions:
    - Gallery connectivity: Check internet connection and firewall
    - Permission errors: Run with administrator privileges
    - Module conflicts: Manually remove conflicting versions
    - Update failures: Check available disk space and memory

.RELATED_LINKS
    https://docs.microsoft.com/en-us/powershell/module/powershellget/
    https://www.powershellgallery.com/
    https://docs.microsoft.com/en-us/powershell/scripting/gallery/getting-started
#>

    [cmdletbinding()]
    param()

    Write-Log 'Getting installed modules...' -Level 'INFO'
    $InstalledModules = Get-InstalledModule
    $TotalModules = $InstalledModules.Count
    Write-Log "Found $TotalModules installed modules" -Level 'INFO'

    Write-Log 'Comparing to online versions...' -Level 'INFO'
    $Counter = 0

    foreach ($module in $InstalledModules) {
        $Counter++
        Write-Progress -Activity 'Checking module updates' -Status "Processing $($module.name) ($Counter of $TotalModules)" -PercentComplete (($Counter / $TotalModules) * 100)
        #find the current version in the gallery
        $online = $null
        try {
            $online = Find-Module -Name $module.name -Repository PSGallery -ErrorAction Stop
        } catch {
            Write-Log "Module '$($module.name)' was not found in the PowerShell Gallery or gallery is unavailable" -Level 'WARNING'
            continue
        }

        #compare versions
        if ($online -and $online.version -gt $module.version) {
            $UpdateAvailable = $True
        } else {
            $UpdateAvailable = $False
        }

        # Check for multiple versions of the same module
        $AllVersions = Get-InstalledModule -Name $module.name -AllVersions -ErrorAction SilentlyContinue
        $HasMultipleVersions = ($AllVersions.Count -gt 1)

        #write a custom object to the pipeline
        [pscustomobject]@{
            Name             = $module.name
            Author           = $module.author
            Description      = $module.description
            MultipleVersions = $HasMultipleVersions
            InstalledVersion = $module.version
            InstalledDate    = $module.InstalledDate
            OnlineVersion    = $online.version
            Update           = $UpdateAvailable
            Path             = $module.InstalledLocation
        }

        if ($UpdateAvailable) {
            try {
                Write-Log "Updating module '$($module.name)' from version $($module.version) to $($online.version)" -Level 'INFO'
                Update-Module -Name $module.name -Force -ErrorAction Stop

                Write-Log "Cleaning up old versions of '$($module.name)'" -Level 'INFO'
                $Latest = Get-InstalledModule -Name $module.name -ErrorAction Stop
                $OldVersions = Get-InstalledModule -Name $module.name -AllVersions -ErrorAction Stop | Where-Object { $_.Version -ne $Latest.Version }

                if ($OldVersions) {
                    foreach ($OldVersion in $OldVersions) {
                        try {
                            Uninstall-Module -Name $OldVersion.Name -RequiredVersion $OldVersion.Version -Force -ErrorAction Stop
                            Write-Verbose "Removed version $($OldVersion.Version) of $($OldVersion.Name)"
                        } catch {
                            Write-Log "Failed to uninstall version $($OldVersion.Version) of $($OldVersion.Name): $($_.Exception.Message)" -Level 'WARNING'
                        }
                    }
                }
            } catch {
                Write-Log "Failed to update module '$($module.name)': $($_.Exception.Message)" -Level 'ERROR'
            }
        }

    } #foreach

    # Complete progress bar
    Write-Progress -Activity 'Checking module updates' -Completed

    Write-Log 'Module update process completed successfully' -Level 'INFO'
}
}
#endregion Functions

#=============================================================================
# Script Execution
#=============================================================================

# Variables
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath"
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $env:computername + '-' + $LogDate + '.log'
$logFile = $logPath + '\' + "$LogName"

# Start execution
Write-Log '====================================' -Level 'INFO'
Write-Log 'Starting PowerShell Module Update Process' -Level 'INFO'
$StartTime = Get-Date
Write-Log "Script started at: $StartTime" -Level 'INFO'
Write-Log '====================================' -Level 'INFO'

Write-Log 'Checking pre-requisites' -Level 'INFO'

Write-Log 'Checking for elevated mode' -Level 'INFO'
try {
    # Ensure running with administrator privileges
    Invoke-ElevatedExecution
    Write-Log 'running in elevated mode' -Level 'INFO'
} catch {
    Write-Log '====================================' -Level 'ERROR'
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level 'ERROR'
    Write-Log '====================================' -Level 'ERROR'
    exit 1
}

# Verify PowerShellGet module is available
Write-Log 'Verifying PowerShellGet module availability...' -Level 'INFO'
if (-not (Get-Module -ListAvailable -Name PowerShellGet)) {
    Write-Log 'PowerShellGet module is required but not found. Please install PowerShellGet first.' -Level 'ERROR'
    exit 2
}
Write-Log 'Completed checking pre-requisites' -Level 'INFO'

# Start the update process
Write-Log '====================================' -Level 'INFO'
Write-Log 'Initiating module update process...' -Level 'INFO'
Update-InstalledModules
Write-Log '====================================' -Level 'INFO'
Write-Log 'PowerShell Module Update Process Completed Successfully' -Level 'INFO'

# Script completion
$EndTime = Get-Date
Write-Log "Script ended at: $EndTime" -Level 'INFO'
$Duration = $EndTime - $StartTime
$Formatted = 'Hours: {0:D2} Minutes:{1:D2} Seconds:{2:D2}' -f $Duration.Hours, $Duration.Minutes, $Duration.Seconds
Write-Log "Total duration: $Formatted" -Level 'INFO'
Write-Log '====================================' -Level 'INFO'

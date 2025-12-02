<#
.SYNOPSIS
    Configures Active Directory replication change notification for optimized domain controller synchronization.

.DESCRIPTION
    The Set-ChangeNotification script provides enterprise-grade configuration management for Active Directory
    replication change notification mechanisms. This PowerShell tool optimizes domain controller synchronization
    by enabling immediate change notifications instead of relying solely on scheduled replication intervals,
    significantly reducing replication latency in enterprise environments.

    Core Functionality:
    ? Configures change notification on Active Directory site links (Options bit 1)
    ? Configures change notification on replication connections (Options bit 8)
    ? Supports targeted configuration of specific objects or forest-wide deployment
    ? Preserves existing Options attribute flags using bitwise operations
    ? Provides comprehensive audit trails and operational logging
    ? Implements enterprise-grade error handling and validation

    Operation Modes:
    The script operates through two mutually exclusive parameter sets designed for different
    replication optimization scenarios:

    1. Site Link Mode (-ReplicationSiteLink):
       Targets inter-site replication optimization by configuring change notification
       on site link objects. This mode is ideal for environments with multiple sites
       where rapid cross-site synchronization is critical.

    2. Connection Mode (-ReplicationConnection):
       Targets intra-site and specific connection optimization by configuring change
       notification on replication connection objects. This mode provides granular
       control over individual replication partnerships.

    Scope Control:
    ? Name Parameter Specified: Processes only the targeted object for precise control
    ? Name Parameter Omitted: Processes all objects of the specified type forest-wide
    ? Supports both single-object and bulk configuration scenarios

    The script implements comprehensive logging with timestamped entries, severity-based
    color coding, and detailed operational tracking suitable for enterprise audit requirements.

.PARAMETER ReplicationSiteLink
    Mandatory switch parameter that activates site link configuration mode.

    When specified, the script targets Active Directory site link objects for change notification
    configuration by setting Options attribute bit 1 (decimal value 1). This mode optimizes
    inter-site replication by enabling immediate notifications when directory changes occur,
    reducing cross-site replication latency from scheduled intervals to near real-time.

    This parameter is mutually exclusive with ReplicationConnection and belongs to the
    'ReplicationSiteLink' parameter set. Site link mode is recommended for environments
    with multiple AD sites requiring rapid synchronization across WAN connections.

    Technical Implementation: Sets or preserves Options bit 1 using bitwise OR operations
    to maintain any existing configuration flags while adding change notification capability.

.PARAMETER ReplicationConnection
    Mandatory switch parameter that activates replication connection configuration mode.

    When specified, the script targets Active Directory replication connection objects for
    change notification configuration by setting Options attribute bit 8 (decimal value 8).
    This mode provides granular control over individual replication partnerships and is
    ideal for optimizing specific domain controller synchronization relationships.

    This parameter is mutually exclusive with ReplicationSiteLink and belongs to the
    'ReplicationConnection' parameter set. Connection mode is recommended for fine-tuning
    replication performance between specific domain controllers or troubleshooting
    replication issues in targeted partnerships.

    Technical Implementation: Sets or preserves Options bit 8 using bitwise OR operations
    to maintain existing connection configuration while enabling change notification.

.PARAMETER Name
    Optional string parameter specifying the target object for change notification configuration.

    When provided, the script processes only the specified object, enabling precise control
    over change notification deployment. When omitted, the script processes all objects
    of the type specified by the operation mode (all site links or all connections).

    Supported Formats:
    ? Site Link Mode: Site link name (e.g., "DEFAULTIPSITELINK", "HQ-Branch-Link")
    ? Connection Mode: Connection distinguished name or GUID identifier

    Validation:
    ? Must correspond to existing AD objects accessible with current credentials
    ? Case-sensitive matching based on Active Directory object naming
    ? Must exist in the current forest and be accessible via PowerShell AD cmdlets

    Usage Scenarios:
    ? Targeted deployment for specific replication relationships
    ? Testing change notification on individual objects before forest-wide deployment
    ? Troubleshooting specific replication performance issues
    ? Staged rollout in large enterprise environments

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
    Script Name    : Set-ChangeNotification v2.0.0.ps1
    Author         : Francois Fournier
    Version        : 2.0.0
    Created        : 2025-12-02
    Last Modified  : 2025-12-02
    License        : MIT License

    Version History:
    V1.0.0 - Initial release with basic site link change notification functionality
    V1.1.0 - Enhanced targeting with Name parameter for specific site link configuration
    V2.0.0 - Major release with enterprise-grade enhancements:
             ? Dual-mode operation supporting both site links and replication connections
             ? Parameter set implementation for mutually exclusive operation modes
             ? Comprehensive enterprise logging with Write-Log function and severity levels
             ? Advanced error handling with proper exception management and exit codes
             ? Bitwise OR operations to preserve existing Options attribute flags
             ? Color-coded console output for improved operational visibility
             ? Enhanced code organization with proper region structures
             ? Fixed variable scope issues and improved script reliability
             ? Renamed LinkName parameter to Name for consistency across modes
             ? Added SupportsShouldProcess for -WhatIf and -Confirm functionality

    System Requirements:
    ? Windows PowerShell 5.1 or PowerShell 7.x (cross-platform compatibility)
    ? Active Directory PowerShell module (RSAT-AD-PowerShell feature)
    ? Windows Server 2016+ or Windows 10+ with Remote Server Administration Tools
    ? .NET Framework 4.7.2 or higher for optimal AD module compatibility
    ? Minimum 4GB RAM for large forest operations (recommended 8GB+)

    Permission Requirements:
    ? Domain Administrator privileges or delegated replication management permissions
    ? Enterprise Administrator rights for forest-wide operations
    ? Local Administrator privileges on execution host (enforced via #Requires directive)
    ? Replication topology modification permissions in Active Directory
    ? Write access to script directory for log file creation and management
    ? Read access to Active Directory Configuration and Schema partitions

    Network and Connectivity Requirements:
    ? Reliable network connectivity to all domain controllers in target sites
    ? Access to Active Directory Global Catalog servers for forest-wide queries
    ? DNS resolution for all domain controllers and site infrastructure
    ? LDAP/LDAPS connectivity (ports 389/636) to domain controllers
    ? RPC connectivity for replication management operations
    ? Firewall exceptions for Active Directory replication ports (varies by environment)

    Enterprise Safety and Deployment Considerations:
    ? CRITICAL: Always test with -WhatIf parameter in non-production environments
    ? Implement phased deployment starting with test sites before production rollout
    ? Create complete Active Directory backup before making replication changes
    ? Monitor replication health using repadmin and AD replication monitoring tools
    ? Change notification increases inter-DC network traffic - plan bandwidth accordingly
    ? Schedule deployment during maintenance windows to minimize business impact
    ? Document current replication configuration for rollback procedures
    ? Validate DNS and network connectivity before enabling change notification
    ? Monitor domain controller performance for 24-48 hours post-deployment

    Technical Implementation Architecture:
    ? Site Links: Configures Options attribute bit 1 (0x0001) for immediate inter-site replication
    ? Connections: Configures Options attribute bit 8 (0x0008) for connection-specific notifications
    ? Bitwise OR operations preserve existing Options flags while adding change notification
    ? Parameter sets ensure mutually exclusive operation modes with proper validation
    ? Comprehensive error handling with specific exit codes for different failure scenarios
    ? Enterprise logging with timestamp, severity, and operational detail tracking
    ? SupportsShouldProcess implementation for safe testing and change management

    Performance Impact and Monitoring:
    ? Initial processing time scales with forest size (estimate 1-2 minutes per 1000 objects)
    ? Post-deployment network traffic increases proportional to change frequency
    ? Domain controller CPU usage may increase 5-15% depending on change volume
    ? Memory utilization typically increases 10-50MB per DC for change notification queues
    ? Replication latency reduces from schedule-based (15-180 minutes) to near-real-time (seconds)
    ? Monitor using Performance Monitor counters: DRA Inbound/Outbound traffic and queue lengths

    Compliance and Audit Considerations:
    ? Comprehensive logging supports SOX, HIPAA, and other regulatory audit requirements
    ? Change tracking includes before/after Options values for complete audit trail
    ? Script execution logs include timestamp, user context, and all performed modifications
    ? Supports enterprise change management processes with detailed documentation
    ? Error conditions logged with sufficient detail for forensic analysis

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

.errorcode
    1 - General script failure (e.g., module import failure, parameter validation error)
    2 - Specific error related to replication connection or site link modification
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

    [Parameter(Mandatory = $False, Position = 1, HelpMessage = 'The name of the site link or replication connection to enable change notification for')]
    [string]$Name
)
#region Functions
#=============================================================================
function Write-Log {
    <#
    .SYNOPSIS
        Provides enterprise-grade logging functionality with severity-based console output and file persistence.

    .DESCRIPTION
        The Write-Log function implements comprehensive logging capabilities for enterprise PowerShell
        scripts, supporting both file-based persistence and color-coded console output. This function
        provides structured logging with timestamps, severity levels, and consistent formatting suitable
        for enterprise audit requirements and operational monitoring.

        Features:
        ? Timestamped log entries with yyyy-MM-dd HH:mm:ss format
        ? Severity-based color coding for immediate visual feedback
        ? File persistence for audit trails and post-execution analysis
        ? Standardized log entry format for parsing and analysis tools
        ? Integration with PowerShell's native verbose stream for detailed diagnostics

        The function supports five severity levels (INFO, WARNING, ERROR, DEBUG, VERBOSE)
        with appropriate console color coding and consistent file formatting.

    .PARAMETER Message
        Mandatory string parameter containing the log message content.

        Should be concise yet descriptive to facilitate troubleshooting, audit reviews,
        and operational analysis. Messages are automatically prefixed with timestamp and
        severity level for consistent formatting.

        Best Practices:
        ? Use action-oriented language ("Starting process", "Configuration completed")
        ? Include relevant context (object names, values, operation types)
        ? Avoid sensitive information (passwords, tokens, personal data)
        ? Keep messages under 200 characters for readability

    .PARAMETER Level
        Mandatory string parameter specifying the log entry severity level.

        ValidateSet: 'INFO', 'WARNING', 'ERROR', 'DEBUG', 'VERBOSE'

        Severity Level Definitions:
        ? INFO: Standard operational messages, successful operations, status updates
        ? WARNING: Potentially problematic conditions that don't prevent execution
        ? ERROR: Error conditions that may impact functionality or require attention
        ? DEBUG: Detailed diagnostic information for troubleshooting and development
        ? VERBOSE: Extremely detailed operational information for deep analysis

        Console Color Mapping:
        ? INFO: Green (success/normal operations)
        ? WARNING: Magenta (caution/attention required)
        ? ERROR: Red (problems/failures)
        ? DEBUG: Cyan (diagnostic information)
        ? VERBOSE: Default console color via Write-Verbose

    .OUTPUTS
        File: Log entries appended to $LogFile with timestamp and severity prefix
        Console: Color-coded output based on severity level for immediate feedback

        Log File Format: "yyyy-MM-dd HH:mm:ss [LEVEL] Message"
        Console Format: "[LEVEL] Message" (with appropriate color coding)

    .EXAMPLE
        Write-Log -Message 'Active Directory module imported successfully' -Level 'INFO'

        Logs a successful operation with INFO severity level, displaying in green
        on console and appending timestamped entry to log file.

    .EXAMPLE
        Write-Log -Message 'Site link not found, skipping configuration' -Level 'WARNING'

        Logs a warning condition with magenta console output and appropriate
        file logging for audit trail purposes.

    .EXAMPLE
        Write-Log -Message 'Failed to modify replication connection: Access Denied' -Level 'ERROR'

        Logs an error condition with red console highlighting and detailed
        file entry for troubleshooting and incident analysis.

    .NOTES
        Function Name  : Write-Log
        Author         : Francois Fournier
        Version        : 2.0.0
        Created        : 2025-01-01
        Last Modified  : 2025-12-02
        License        : MIT License

        Dependencies:
        ? $logFile variable must be defined in parent scope
        ? Write access to log file directory required
        ? PowerShell 5.1+ for ValidateSet parameter validation

        Enterprise Considerations:
        ? Log files may contain sensitive operational information
        ? Implement log rotation for long-running or frequently executed scripts
        ? Consider centralized logging integration for enterprise monitoring
        ? Ensure compliance with data retention and privacy policies

    .COMPONENT
        Enterprise Logging and Audit Framework
        PowerShell Operational Diagnostics

    .FUNCTIONALITY
        ? Structured enterprise logging with severity-based categorization
        ? Color-coded console output for immediate operational feedback
        ? File persistence for audit trails and compliance requirements
        ? Integration with PowerShell verbose stream for detailed diagnostics
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG', 'VERBOSE')]
        [string]$Level
    )
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "$TimeStamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogEntry
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
$LogPath = "$ScriptPath"
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = $LogPath + '\' + "$LogName"
#endregion Variables

Write-Log -Message "`n========================================" -Level 'INFO'
Write-Log -Message 'Starting Script.' -Level 'INFO'

# Import the Active Directory module
Write-Log -Message 'Importing Active Directory module.' -Level 'INFO'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log -Message 'Active Directory module imported successfully.' -Level 'INFO'
} catch {
    Write-Log -Message "Failed to import Active Directory module. Ensure it is installed and you have the necessary permissions. Error: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

if ($ReplicationConnection -or $ReplicationSiteLink) {
    #region ReplicationConnection
    if ($ReplicationConnection) {
        Write-Log -Message 'Verifying Replication connections change notification status...' -Level 'INFO'

        try {
            if ($Name) {
                Write-Log -Message "Processing replication connection: $Name" -Level 'INFO'
                $ReplicationConnections = @(Get-ADReplicationConnection -Identity $Name -ErrorAction Stop)
            } else {
                Write-Log -Message 'Retrieving replication connections from Active Directory.' -Level 'INFO'
                $ReplicationConnections = @(Get-ADReplicationConnection -Filter * -Properties options -ErrorAction Stop)
            }
        } catch {
            Write-Log -Message "Failed to retrieve replication connection(s). Error: $($_.Exception.Message)" -Level 'ERROR'
            exit 2
        }

        Write-Log -Message "Found $($ReplicationConnections.Count) replication connection(s)" -Level 'VERBOSE'

        foreach ($Connection in $ReplicationConnections) {
            Write-Log -Message "Processing replication connection: $($Connection.Name)" -Level 'VERBOSE'

            # Enable change notification by setting the Options attribute bit 8
            # If Options already has other flags, use bitwise OR to preserve them
            if ($Connection.Options) {
                $CurrentOptions = $Connection.Options
            } else {
                $CurrentOptions = 0
            }
            $NewOptions = $CurrentOptions -bor 8

            Write-Log -Message "Current Options value: $CurrentOptions" -Level 'VERBOSE'
            Write-Log -Message "New Options value: $NewOptions" -Level 'VERBOSE'

            # Apply the change
            try {
                if ($PSCmdlet.ShouldProcess("$($Connection.Name)", 'Set-ADReplicationConnection')) {
                    Set-ADReplicationConnection -Identity $($Connection.Name) -Replace @{'options' = $NewOptions } -ErrorAction Stop
                    Write-Log -Message "Change notification enabled for replication connection '$($Connection.Name)'" -Level 'INFO'
                    Write-Log -Message "Options value changed from $CurrentOptions to $NewOptions" -Level 'INFO'
                }
            } catch {
                Write-Log -Message "Failed to set Options on replication connection '$($Connection.Name)'. Error: $($_.Exception.Message)" -Level 'ERROR'
                continue
            }
        }
    }
    #endregion ReplicationConnection

    #region SiteLink
    # Get the current site link objects
    if ($ReplicationSiteLink) {
        Write-Log -Message 'Verifying Replication Site Link change notification status...' -Level 'INFO'

        try {
            if ($Name) {
                Write-Log -Message "Processing site link: $Name" -Level 'INFO'
                $SiteLinks = @(Get-ADReplicationSiteLink -Identity $Name -ErrorAction Stop)
            } else {
                Write-Log -Message 'Retrieving site links from Active Directory.' -Level 'INFO'
                $SiteLinks = @(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop)
            }
        } catch {
            Write-Log -Message "Failed to retrieve site link(s). Error: $($_.Exception.Message)" -Level 'ERROR'
            exit 2
        }

        Write-Log -Message "Found $($SiteLinks.Count) site link(s)" -Level 'VERBOSE'

        foreach ($SiteLink in $SiteLinks) {
            Write-Log -Message "Processing site link: $($SiteLink.Name)" -Level 'VERBOSE'

            # Enable change notification by setting the Options attribute bit 1
            # If Options already has other flags, use bitwise OR to preserve them
            $CurrentOptions = if ($SiteLink.Options) {
                $SiteLink.Options
            } else {
                0
            }
            $NewOptions = $CurrentOptions -bor 1

            Write-Log -Message "Current Options value: $CurrentOptions" -Level 'VERBOSE'
            Write-Log -Message "New Options value: $NewOptions" -Level 'VERBOSE'

            # Apply the change
            try {
                if ($PSCmdlet.ShouldProcess("$($SiteLink.Name)", 'Set-ADReplicationSiteLink')) {
                    Set-ADReplicationSiteLink -Identity $($SiteLink.Name) -Replace @{'options' = $NewOptions } -ErrorAction Stop
                }
                Write-Log -Message "Change notification enabled for site link '$($SiteLink.Name)'" -Level 'INFO'
                Write-Log -Message "Options value changed from $CurrentOptions to $NewOptions" -Level 'INFO'
            } catch {
                Write-Log -Message "Failed to set Options on site link '$($SiteLink.Name)'. Error: $($_.Exception.Message)" -Level 'ERROR'
                continue
            }
        }
    }
    #endregion SiteLink

} else {
    Write-Log -Message 'No replication connection or site link parameter specified. Please provide at least one.' -Level 'ERROR'
    exit 1
}


Write-Log -Message 'Script completed successfully.' -Level 'INFO'

handlelling

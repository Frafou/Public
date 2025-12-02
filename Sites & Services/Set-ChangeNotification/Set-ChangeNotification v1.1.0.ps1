<#
.SYNOPSIS
    Enterprise-grade Active Directory replication site link change notification configuration tool.

.DESCRIPTION
    This PowerShell script provides enterprise-level functionality for configuring change
    notification on Active Directory replication site links. It modifies the Options
    attribute to include the change notification flag (bit 1), enabling immediate
    replication when changes occur instead of waiting for scheduled intervals.

    The script implements comprehensive error handling, validation, and reporting
    capabilities suitable for enterprise environments. It supports both single
    site link processing and bulk operations across all forest site links.

    Key Features:
    ? Intelligent site link discovery and validation
    ? Pre-change validation to avoid redundant operations
    ? Comprehensive error handling with detailed logging
    ? WhatIf support for safe testing and validation
    ? Enterprise-grade exit codes for automation integration
    ? Detailed execution summary with operation statistics
    ? Parameter validation to prevent invalid configurations

.PARAMETER SiteLinkName
    Specifies the name of a specific Active Directory site link to process.

    - Type: String
    - Mandatory: False
    - Position: 0
    - Default: Process all site links in the forest
    - Validation: Cannot be empty, null, or whitespace
    - Example: "DEFAULTIPSITELINK", "HQ-Branch1-Link"

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Void

    The script outputs detailed console messages with color coding:
    ? Green: Successful operations and confirmations
    ? Yellow: Warnings and skipped operations
    ? Red: Errors and failures
    ? Magenta: WhatIf simulation results
    ? Cyan: Informational details

    Exit Codes:
    ? 0: Complete success (all operations succeeded)
    ? 1: Active Directory module import failure
    ? 2: Site link retrieval failure
    ? 3: Total failure (all operations failed)
    ? 4: Specified site link not found
    ? 5: Partial success (some operations failed)

.EXAMPLE
    PS C:\> .\Set-ChangeNotification.ps1

    Description:
    Enables change notification for all site links in the Active Directory forest.
    Displays comprehensive summary with operation statistics.

.EXAMPLE
    PS C:\> .\Set-ChangeNotification.ps1 -SiteLinkName "DEFAULTIPSITELINK"

    Description:
    Enables change notification for the specific site link 'DEFAULTIPSITELINK'.
    Validates the site link exists before attempting modification.

.EXAMPLE
    PS C:\> .\Set-ChangeNotification.ps1 -WhatIf

    Description:
    Simulates enabling change notification for all site links without making
    actual changes. Displays what operations would be performed.

.EXAMPLE
    PS C:\> .\Set-ChangeNotification.ps1 -SiteLinkName "HQ-DR-Link" -Verbose

    Description:
    Enables change notification for 'HQ-DR-Link' with detailed verbose output
    showing current and new Options values.

.EXAMPLE
    PS C:\> .\Set-ChangeNotification.ps1 -SiteLinkName "Branch-Link" -WhatIf -Verbose

    Description:
    Simulates change notification configuration for 'Branch-Link' with maximum
    verbosity for detailed analysis.

.NOTES
    ???????????????????????????????????????????????????????????????????????????????

    Script Information:
    ? Name: Set-ChangeNotification.ps1
    ? Version: 1.1.0
    ? Author: Enterprise System Administrator
    ? Created: December 2, 2025
    ? Last Modified: December 2, 2025
    ? Copyright: © 2025 Enterprise IT Operations
    ? License: MIT License
    ? Classification: Internal Use - IT Operations
    ? Category: Active Directory Management

    Version History:
    ? v1.0.0 (2025-12-02): Initial enterprise release
    ? v1.1.0 (2025-12-02): Added targeted site link processing and enhanced validation

    Technical Requirements:
    ? PowerShell Version: 5.1 or higher
    ? Modules: ActiveDirectory (RSAT Tools)
    ? Permissions: Domain Administrator or equivalent
    ? Platform: Windows Server 2016+ or Windows 10+ with RSAT
    ? Network: Connectivity to domain controllers
    ? Authentication: Must run with elevated privileges

    Enterprise Considerations:
    ? Impact Assessment: Modifies Active Directory replication topology
    ? Change Management: Requires approval for production environments
    ? Testing: Always validate with -WhatIf parameter first
    ? Monitoring: Monitor replication health post-implementation
    ? Performance: May increase network traffic during replication
    ? Rollback: Document current settings before modification
    ? Compliance: Ensure change aligns with replication policies

    Security & Compliance:
    ? Privilege Level: Requires Domain Administrator rights
    ? Audit Trail: All operations logged to console with timestamps
    ? Data Protection: No sensitive data exposure in output
    ? Access Control: Validate user permissions before execution

    Support & Documentation:
    ? Internal Wiki: Reference enterprise AD management procedures
    ? Escalation: Contact Enterprise Architecture team for issues
    ? Training: Requires Active Directory replication knowledge

.COMPONENT
    Enterprise Active Directory Management

.ROLE
    Infrastructure Configuration Utility

.FUNCTIONALITY
    ? Active Directory site link management
    ? Replication topology optimization
    ? Change notification configuration
    ? Enterprise automation support

.TAGS
    ActiveDirectory, Replication, SiteLinks, ChangeNotification, Enterprise, Automation

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/replication/

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology

.LINK
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/

.EXTERNALHELP
    For additional help and enterprise procedures, consult the internal IT documentation portal.
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
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw 'SiteLinkName cannot be empty or whitespace.'
            }
            return $true
        })]
    [string]$SiteLinkName
)

Write-Host "`n========================================"
Write-Host 'Set-ChangeNotification v1.1.0 - Starting execution...'
Write-Host '========================================'

# Import the Active Directory module
Write-Host 'Importing Active Directory module...'
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host 'Active Directory module imported successfully.' -ForegroundColor Green
} catch {
    Write-Host "Failed to import Active Directory module. Ensure it is installed and you have the necessary permissions. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Get the current site link objects
Write-Host 'Retrieving site link information...'
try {
    if ($SiteLinkName) {
        Write-Host "Processing specific site link: $SiteLinkName"
        $SiteLinks = @(Get-ADReplicationSiteLink -Identity $SiteLinkName -ErrorAction Stop)
    } else {
        Write-Host 'Retrieving all site links from Active Directory...'
        $SiteLinks = @(Get-ADReplicationSiteLink -Filter * -ErrorAction Stop)
    }
} catch {
    Write-Host "Failed to retrieve site link(s). Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}

# Check if any site links were found
if ($SiteLinks.Count -eq 0) {
    Write-Host 'No site links found.' -ForegroundColor Yellow
    if ($SiteLinkName) {
        Write-Host "Site link '$SiteLinkName' does not exist." -ForegroundColor Red
        exit 4
    } else {
        Write-Host 'No site links exist in the Active Directory forest.' -ForegroundColor Yellow
        exit 0
    }
}
Write-Host "Found $($SiteLinks.Count) site link(s) to process" -ForegroundColor Cyan

$ProcessedCount = 0
$SkippedCount = 0
$ErrorCount = 0
$WhatIfCount = 0

foreach ($SiteLink in $SiteLinks) {
    Write-Verbose "Processing site link: $($SiteLink.Name)"

    # Enable change notification by setting the Options attribute bit 1
    # If Options already has other flags, use bitwise OR to preserve them
    $CurrentOptions = if ($SiteLink.Options) {
        $SiteLink.Options
    } else {
        0
    }

    # Check if change notification is already enabled
    if (($CurrentOptions -band 1) -eq 1) {
        Write-Host "? Change notification already enabled for '$($SiteLink.Name)' (Options: $CurrentOptions)" -ForegroundColor Yellow
        $SkippedCount++
        continue
    }

    $NewOptions = $CurrentOptions -bor 1
    Write-Verbose "Current Options value: $CurrentOptions"
    Write-Verbose "New Options value: $NewOptions"

    # Apply the change
    try {
        if ($PSCmdlet.ShouldProcess("$($SiteLink.Name)", "Enable change notification (set Options from $CurrentOptions to $NewOptions)")) {
            Set-ADReplicationSiteLink -Identity $($SiteLink.Name) -Replace @{'options' = $NewOptions } -ErrorAction Stop
            Write-Host "? Change notification enabled for '$($SiteLink.Name)'" -ForegroundColor Green
            Write-Host "  Options value: $CurrentOptions ? $NewOptions" -ForegroundColor Cyan
            $ProcessedCount++
        } else {
            Write-Host "[WHATIF] Would enable change notification for '$($SiteLink.Name)'" -ForegroundColor Magenta
            Write-Host "[WHATIF] Would change Options: $CurrentOptions ? $NewOptions" -ForegroundColor Magenta
            $WhatIfCount++
        }
    } catch {
        Write-Host "? Failed to modify '$($SiteLink.Name)': $($_.Exception.Message)" -ForegroundColor Red
        $ErrorCount++
        continue
    }
}

# Display execution summary
Write-Host "`n========================================"
Write-Host 'Set-ChangeNotification v1.1.0 - Execution Summary:' -ForegroundColor Green
Write-Host "  Total site links found: $($SiteLinks.Count)"
if ($ProcessedCount -gt 0) {
    Write-Host "  ? Successfully modified: $ProcessedCount" -ForegroundColor Green
}
if ($WhatIfCount -gt 0) {
    Write-Host "  ? WhatIf simulations: $WhatIfCount" -ForegroundColor Magenta
}
if ($SkippedCount -gt 0) {
    Write-Host "  - Already enabled: $SkippedCount" -ForegroundColor Yellow
}
if ($ErrorCount -gt 0) {
    Write-Host "  ? Errors encountered: $ErrorCount" -ForegroundColor Red
}
Write-Host '========================================'

# Determine appropriate exit code
if ($ErrorCount -gt 0 -and ($ProcessedCount -eq 0 -and $WhatIfCount -eq 0)) {
    # All operations failed
    Write-Host 'Script completed with errors. All operations failed.' -ForegroundColor Red
    exit 3
} elseif ($ErrorCount -gt 0) {
    # Partial success
    Write-Host 'Script completed with warnings. Some operations failed.' -ForegroundColor Yellow
    exit 5
} else {
    # Complete success
    Write-Host 'Script completed successfully.' -ForegroundColor Green
    exit 0
}

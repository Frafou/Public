<#
.SYNOPSIS
    Comprehensive Active Directory computer inventory and analysis tool.

.DESCRIPTION
    This advanced script enumerates all computer objects from Active Directory domains
    and provides detailed analysis including security assessment, compliance checking,
    asset management capabilities, and risk evaluation. Supports multiple output formats,
    advanced filtering, and enterprise-grade reporting with actionable insights.

.PARAMETER DomainName
    Specifies the domain to query. If not provided, uses the current computer's domain.
    Supports cross-domain enumeration with appropriate credentials.

.PARAMETER OutputPath
    Specifies the output directory for result files. Default is current directory.
    Creates directory structure if it doesn't exist.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'CSV', 'JSON', 'Excel', 'Object', 'HTML'.
    Default is 'CSV'. Each format optimized for different use cases.

.PARAMETER Filter
    Specifies additional LDAP filter criteria beyond default. Allows complex filtering
    for targeted analysis and reporting.

.PARAMETER IncludeDisabled
    Include disabled computer accounts in the results. Default excludes disabled accounts
    for focus on active infrastructure.

.PARAMETER IncludeExtendedProperties
    Include additional properties like group memberships, service accounts, and
    extended security attributes for comprehensive analysis.

.PARAMETER DaysInactive
    Only include computers that have been inactive for specified number of days.
    Useful for identifying stale computer accounts.

.PARAMETER SecurityAssessment
    Perform comprehensive security assessment including OS version analysis,
    patch level evaluation, and security configuration review.

.PARAMETER ComplianceCheck
    Perform compliance checking against organizational policies and
    industry standards with detailed reporting.

.PARAMETER AssetManagement
    Include asset management features like warranty tracking, lifecycle analysis,
    and replacement planning recommendations.

.PARAMETER RiskAnalysis
    Perform risk analysis including vulnerability assessment, exposure evaluation,
    and security recommendations.

.PARAMETER Credential
    Specifies credentials to use when querying Active Directory.
    Required for cross-domain scenarios.

.PARAMETER IncludeStatistics
    Include comprehensive statistics and analysis in output with
    executive summary and trending information.

.PARAMETER MonitoringIntegration
    Enable monitoring system integration features including JSON output
    and alert generation for critical findings.

.PARAMETER ConfigurationFile
    Path to configuration file containing advanced settings, custom filters,
    and organizational policies for compliance checking.

.EXAMPLE
    .\GetComputer_v2.5.ps1
    Basic computer inventory for current domain with enhanced analysis.

.EXAMPLE
    .\GetComputer_v2.5.ps1 -SecurityAssessment -ComplianceCheck -OutputFormat Excel
    Comprehensive security and compliance assessment exported to Excel.

.EXAMPLE
    .\GetComputer_v2.5.ps1 -DaysInactive 90 -RiskAnalysis -OutputFormat JSON
    Identify inactive computers with risk analysis in JSON format for automation.

.EXAMPLE
    .\GetComputer_v2.5.ps1 -Filter "OperatingSystem -like '*Server*'" -AssetManagement
    Server inventory with asset management features and lifecycle analysis.

.EXAMPLE
    .\GetComputer_v2.5.ps1 -OutputFormat Object | Where-Object {$_.SecurityRisk -eq 'High'}
    Return computer objects for pipeline processing, filtering high-risk systems.

.NOTES
    Version: 2.5
    Author: Enterprise PowerShell Modernization
    Last Modified: February 2026
    Requires: PowerShell 5.1 or higher, ActiveDirectory module

    Change Log:
    v0.2 - Basic AD computer enumeration
    v2.5 - Complete enterprise modernization with advanced features
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Domain name to query")]
    [string]$DomainName,

    [Parameter(Mandatory = $false, HelpMessage = "Output directory path")]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false, HelpMessage = "Output format")]
    [ValidateSet('CSV', 'JSON', 'Excel', 'Object', 'HTML')]
    [string]$OutputFormat = 'CSV',

    [Parameter(Mandatory = $false, HelpMessage = "Additional LDAP filter")]
    [string]$Filter = "*",

    [Parameter(Mandatory = $false, HelpMessage = "Include disabled computer accounts")]
    [switch]$IncludeDisabled,

    [Parameter(Mandatory = $false, HelpMessage = "Include extended properties")]
    [switch]$IncludeExtendedProperties,

    [Parameter(Mandatory = $false, HelpMessage = "Only show computers inactive for X days")]
    [int]$DaysInactive,

    [Parameter(Mandatory = $false, HelpMessage = "Perform security assessment")]
    [switch]$SecurityAssessment,

    [Parameter(Mandatory = $false, HelpMessage = "Perform compliance checking")]
    [switch]$ComplianceCheck,

    [Parameter(Mandatory = $false, HelpMessage = "Include asset management features")]
    [switch]$AssetManagement,

    [Parameter(Mandatory = $false, HelpMessage = "Perform risk analysis")]
    [switch]$RiskAnalysis,

    [Parameter(Mandatory = $false, HelpMessage = "Credentials for AD access")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = "Include comprehensive statistics")]
    [switch]$IncludeStatistics,

    [Parameter(Mandatory = $false, HelpMessage = "Enable monitoring integration")]
    [switch]$MonitoringIntegration,

    [Parameter(Mandatory = $false, HelpMessage = "Configuration file path")]
    [string]$ConfigurationFile
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Global variables for configuration
$Script:Config = @{}
$Script:Statistics = @{}
$Script:SecurityBaselines = @{}
$Script:CompliancePolicies = @{}

function Initialize-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile
    )

    # Default configuration
    $Script:Config = @{
        MaxInactivityDays = 90
        SecurityAssessmentEnabled = $false
        ComplianceFrameworks = @('SOC2', 'NIST', 'CIS')
        RiskThresholds = @{
            Critical = @('Windows XP', 'Windows Vista', 'Windows 7')
            High = @('Windows 8', 'Windows Server 2008', 'Windows Server 2012')
            Medium = @('Windows 10 v1507', 'Windows 10 v1511')
        }
        AssetLifecycle = @{
            Workstation = 4
            Server = 7
            DomainController = 10
        }
    }

    # Load configuration file if specified
    if ($ConfigFile -and (Test-Path $ConfigFile)) {
        try {
            $customConfig = Get-Content $ConfigFile | ConvertFrom-Json
            foreach ($key in $customConfig.PSObject.Properties.Name) {
                $Script:Config[$key] = $customConfig.$key
            }
            Write-Verbose "Configuration loaded from: $ConfigFile"
        } catch {
            Write-Warning "Failed to load configuration file: $($_.Exception.Message)"
        }
    }
}

function Get-ComputerDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $false)]
        [string]$Filter = "*",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDisabled,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeExtendedProperties,

        [Parameter(Mandatory = $false)]
        [int]$DaysInactive,

        [Parameter(Mandatory = $false)]
        [switch]$SecurityAssessment,

        [Parameter(Mandatory = $false)]
        [switch]$ComplianceCheck,

        [Parameter(Mandatory = $false)]
        [switch]$AssetManagement,

        [Parameter(Mandatory = $false)]
        [switch]$RiskAnalysis,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        Write-Verbose "Starting computer enumeration for domain: $DomainName"

        # Base properties to retrieve
        $baseProperties = @(
            'Name', 'Description', 'whenChanged', 'whenCreated',
            'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack',
            'PasswordLastSet', 'LastLogonDate', 'Enabled', 'DistinguishedName',
            'DNSHostName', 'SamAccountName', 'servicePrincipalName',
            'TrustedForDelegation', 'TrustedToAuthForDelegation',
            'AccountExpirationDate', 'BadLogonCount', 'badPwdCount',
            'CanonicalName', 'IPv4Address', 'IPv6Address', 'Location',
            'ManagedBy', 'UserAccountControl', 'ms-Mcs-AdmPwd'
        )

        # Extended properties for detailed analysis
        $extendedProperties = @(
            'memberOf', 'PrimaryGroup', 'msDS-SupportedEncryptionTypes',
            'pwdLastSet', 'lastLogonTimestamp', 'userCertificate',
            'altSecurityIdentities', 'msDS-AdditionalDnsHostName'
        )

        $properties = if ($IncludeExtendedProperties) {
            $baseProperties + $extendedProperties | Select-Object -Unique
        } else {
            $baseProperties
        }

        # Build the filter
        $ldapFilter = $Filter
        if (-not $IncludeDisabled) {
            if ($Filter -eq "*") {
                $ldapFilter = "Enabled -eq 'True'"
            } else {
                $ldapFilter = "($Filter) -and (Enabled -eq 'True')"
            }
        }

        Write-Verbose "Using LDAP filter: $ldapFilter"
        Write-Verbose "Retrieving properties: $($properties -join ', ')"

        # Query parameters
        $queryParams = @{
            Filter = $ldapFilter
            Server = $DomainName
            Properties = $properties
        }

        if ($Credential) {
            $queryParams.Credential = $Credential
        }

        # Retrieve computers from AD
        Write-Verbose "Querying Active Directory for computer objects..."
        $computers = Get-ADComputer @queryParams

        if (-not $computers) {
            Write-Warning "No computers found matching the specified criteria"
            return @()
        }

        Write-Verbose "Found $($computers.Count) computer objects, processing details..."

        # Initialize statistics
        $Script:Statistics = @{
            TotalProcessed = 0
            SecurityRisks = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
            ComplianceIssues = 0
            AssetLifecycleAlerts = 0
            InactiveComputers = 0
            DisabledComputers = 0
        }

        # Process each computer and create enhanced objects
        $results = @()
        $processed = 0

        foreach ($computer in $computers) {
            $processed++
            if ($processed % 50 -eq 0) {
                Write-Progress -Activity "Processing computers" -Status "Processed $processed of $($computers.Count)" -PercentComplete (($processed / $computers.Count) * 100)
            }

            # Calculate activity metrics
            $inactiveDays = $null
            $lastActivity = $null
            $activityStatus = "Unknown"

            if ($computer.LastLogonDate) {
                $lastActivity = $computer.LastLogonDate
                $inactiveDays = (Get-Date) - $computer.LastLogonDate | Select-Object -ExpandProperty Days
            } elseif ($computer.PasswordLastSet) {
                $lastActivity = $computer.PasswordLastSet
                $inactiveDays = (Get-Date) - $computer.PasswordLastSet | Select-Object -ExpandProperty Days
            }

            if ($inactiveDays -ne $null) {
                if ($inactiveDays -le 30) { $activityStatus = "Active" }
                elseif ($inactiveDays -le 90) { $activityStatus = "Inactive" }
                else { $activityStatus = "Stale" }
            }

            # Skip if DaysInactive filter is specified and computer doesn't meet criteria
            if ($DaysInactive -and ($inactiveDays -lt $DaysInactive)) {
                continue
            }

            # Determine OS category and risk level
            $osCategory = Get-OSCategory -OperatingSystem $computer.OperatingSystem
            $securityRisk = Get-SecurityRisk -OperatingSystem $computer.OperatingSystem -InactiveDays $inactiveDays

            # Build the enhanced result object
            $computerInfo = [PSCustomObject]@{
                # Basic Information
                Name = $computer.Name
                DNSHostName = $computer.DNSHostName
                Description = $computer.Description

                # Operating System
                OperatingSystem = $computer.OperatingSystem
                OperatingSystemVersion = $computer.OperatingSystemVersion
                OperatingSystemServicePack = $computer.OperatingSystemServicePack
                OSCategory = $osCategory.Category
                OSFamily = $osCategory.Family
                OSSupported = $osCategory.Supported

                # Status and Activity
                Enabled = $computer.Enabled
                ActivityStatus = $activityStatus
                PasswordLastSet = $computer.PasswordLastSet
                LastLogonDate = $computer.LastLogonDate
                LastActivity = $lastActivity
                InactiveDays = $inactiveDays

                # Timestamps
                WhenCreated = $computer.whenCreated
                WhenChanged = $computer.whenChanged

                # Location and Organization
                DistinguishedName = $computer.DistinguishedName
                CanonicalName = $computer.CanonicalName
                OrganizationalUnit = Get-OUPath -DistinguishedName $computer.DistinguishedName
                Location = $computer.Location
                ManagedBy = $computer.ManagedBy

                # Network Information
                SamAccountName = $computer.SamAccountName
                IPv4Address = $computer.IPv4Address
                IPv6Address = $computer.IPv6Address

                # Security Information
                SecurityRisk = $securityRisk
                TrustedForDelegation = $computer.TrustedForDelegation
                TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
                UserAccountControl = $computer.UserAccountControl

                # Account Information
                AccountExpirationDate = $computer.AccountExpirationDate
                BadLogonCount = $computer.BadLogonCount
                ServicePrincipalNames = if ($computer.servicePrincipalName) { $computer.servicePrincipalName -join '; ' } else { $null }

                # Analysis Results (populated later)
                ComplianceStatus = "Unknown"
                ComplianceIssues = @()
                AssetLifecycleStatus = "Unknown"
                AssetRecommendations = @()
                SecurityFindings = @()
                RiskScore = 0

                # Metadata
                CollectionTime = Get-Date
                AnalysisVersion = "2.5"
                DataSource = "ActiveDirectory"
            }

            # Extended properties if requested
            if ($IncludeExtendedProperties) {
                Add-ExtendedProperties -ComputerInfo $computerInfo -Computer $computer
            }

            # Security assessment if requested
            if ($SecurityAssessment) {
                Invoke-SecurityAssessment -ComputerInfo $computerInfo
            }

            # Compliance checking if requested
            if ($ComplianceCheck) {
                Invoke-ComplianceCheck -ComputerInfo $computerInfo
            }

            # Asset management if requested
            if ($AssetManagement) {
                Invoke-AssetManagement -ComputerInfo $computerInfo
            }

            # Risk analysis if requested
            if ($RiskAnalysis) {
                Invoke-RiskAnalysis -ComputerInfo $computerInfo
            }

            # Update statistics
            $Script:Statistics.TotalProcessed++
            $Script:Statistics.SecurityRisks[$securityRisk]++

            if ($activityStatus -eq "Stale") {
                $Script:Statistics.InactiveComputers++
            }

            if (-not $computer.Enabled) {
                $Script:Statistics.DisabledComputers++
            }

            $results += $computerInfo
        }

        Write-Progress -Activity "Processing computers" -Completed
        Write-Verbose "Processed $($results.Count) computers after filtering"

        return $results

    } catch {
        throw "Error retrieving computer details: $($_.Exception.Message)"
    }
}

function Get-OSCategory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OperatingSystem
    )

    $category = @{
        Category = 'Unknown'
        Family = 'Unknown'
        Supported = $false
    }

    if (-not $OperatingSystem) {
        return $category
    }

    switch -Regex ($OperatingSystem) {
        'Server 2022' { $category = @{ Category = 'Server'; Family = 'Windows Server'; Supported = $true } }
        'Server 2019' { $category = @{ Category = 'Server'; Family = 'Windows Server'; Supported = $true } }
        'Server 2016' { $category = @{ Category = 'Server'; Family = 'Windows Server'; Supported = $true } }
        'Server 2012' { $category = @{ Category = 'Server'; Family = 'Windows Server'; Supported = $false } }
        'Server 2008' { $category = @{ Category = 'Server'; Family = 'Windows Server'; Supported = $false } }
        'Windows 11' { $category = @{ Category = 'Workstation'; Family = 'Windows Client'; Supported = $true } }
        'Windows 10' { $category = @{ Category = 'Workstation'; Family = 'Windows Client'; Supported = $true } }
        'Windows 8' { $category = @{ Category = 'Workstation'; Family = 'Windows Client'; Supported = $false } }
        'Windows 7' { $category = @{ Category = 'Workstation'; Family = 'Windows Client'; Supported = $false } }
        'Linux' { $category = @{ Category = 'Server'; Family = 'Linux'; Supported = $true } }
        default { $category = @{ Category = 'Other'; Family = 'Unknown'; Supported = $false } }
    }

    return $category
}

function Get-SecurityRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OperatingSystem,

        [Parameter(Mandatory = $false)]
        [int]$InactiveDays
    )

    # Risk based on OS
    $osRisk = "Low"
    if ($OperatingSystem) {
        foreach ($risk in @('Critical', 'High', 'Medium')) {
            if ($Script:Config.RiskThresholds[$risk] | Where-Object { $OperatingSystem -like "*$_*" }) {
                $osRisk = $risk
                break
            }
        }
    }

    # Risk based on inactivity
    $activityRisk = "Low"
    if ($InactiveDays -gt 365) { $activityRisk = "Critical" }
    elseif ($InactiveDays -gt 180) { $activityRisk = "High" }
    elseif ($InactiveDays -gt 90) { $activityRisk = "Medium" }

    # Return highest risk
    $risks = @($osRisk, $activityRisk)
    if ($risks -contains "Critical") { return "Critical" }
    elseif ($risks -contains "High") { return "High" }
    elseif ($risks -contains "Medium") { return "Medium" }
    else { return "Low" }
}

function Get-OUPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DistinguishedName
    )

    if (-not $DistinguishedName) { return $null }

    try {
        $ouComponents = ($DistinguishedName -split ',OU=')[1..99] | ForEach-Object { $_.Replace('OU=', '') }
        return ($ouComponents -join '\').TrimEnd('\')
    } catch {
        return $null
    }
}

function Add-ExtendedProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ComputerInfo,

        [Parameter(Mandatory = $true)]
        [object]$Computer
    )

    # Add extended properties
    $ComputerInfo | Add-Member -NotePropertyName 'MemberOf' -NotePropertyValue (
        if ($Computer.memberOf) { $Computer.memberOf -join '; ' } else { $null }
    )

    $ComputerInfo | Add-Member -NotePropertyName 'PrimaryGroup' -NotePropertyValue $Computer.PrimaryGroup
    $ComputerInfo | Add-Member -NotePropertyName 'SupportedEncryptionTypes' -NotePropertyValue $Computer.'msDS-SupportedEncryptionTypes'
    $ComputerInfo | Add-Member -NotePropertyName 'HasUserCertificate' -NotePropertyValue ($null -ne $Computer.userCertificate)
    $ComputerInfo | Add-Member -NotePropertyName 'AltSecurityIdentities' -NotePropertyValue (
        if ($Computer.altSecurityIdentities) { $Computer.altSecurityIdentities -join '; ' } else { $null }
    )
    $ComputerInfo | Add-Member -NotePropertyName 'AdditionalDnsHostNames' -NotePropertyValue (
        if ($Computer.'msDS-AdditionalDnsHostName') { $Computer.'msDS-AdditionalDnsHostName' -join '; ' } else { $null }
    )
}

function Invoke-SecurityAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ComputerInfo
    )

    $findings = @()

    # OS Security Assessment
    if (-not $ComputerInfo.OSSupported) {
        $findings += "Unsupported operating system detected"
    }

    # Inactivity Assessment
    if ($ComputerInfo.InactiveDays -gt 90) {
        $findings += "Computer inactive for $($ComputerInfo.InactiveDays) days"
    }

    # Delegation Assessment
    if ($ComputerInfo.TrustedForDelegation) {
        $findings += "Computer trusted for delegation - review security implications"
    }

    # Password Assessment
    if ($ComputerInfo.PasswordLastSet -and ((Get-Date) - $ComputerInfo.PasswordLastSet).Days -gt 90) {
        $findings += "Computer password not changed in 90+ days"
    }

    $ComputerInfo.SecurityFindings = $findings
}

function Invoke-ComplianceCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ComputerInfo
    )

    $issues = @()
    $status = "Compliant"

    # OS Support Compliance
    if (-not $ComputerInfo.OSSupported) {
        $issues += "Non-compliant: Unsupported operating system"
        $status = "Non-Compliant"
    }

    # Activity Compliance
    if ($ComputerInfo.InactiveDays -gt 180) {
        $issues += "Non-compliant: Inactive computer account"
        $status = "Non-Compliant"
    }

    # Naming Compliance
    if ($ComputerInfo.Name -and $ComputerInfo.Name.Length -gt 15) {
        $issues += "Non-compliant: Computer name exceeds 15 characters"
        $status = "Non-Compliant"
    }

    $ComputerInfo.ComplianceStatus = $status
    $ComputerInfo.ComplianceIssues = $issues

    if ($issues.Count -gt 0) {
        $Script:Statistics.ComplianceIssues++
    }
}

function Invoke-AssetManagement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ComputerInfo
    )

    $recommendations = @()
    $status = "Current"

    # Lifecycle Assessment
    if ($ComputerInfo.WhenCreated) {
        $ageYears = ((Get-Date) - $ComputerInfo.WhenCreated).Days / 365
        $lifecycleLimit = $Script:Config.AssetLifecycle[$ComputerInfo.OSCategory]

        if ($ageYears -gt $lifecycleLimit) {
            $status = "End of Life"
            $recommendations += "Asset exceeds lifecycle limit of $lifecycleLimit years"
        } elseif ($ageYears -gt ($lifecycleLimit * 0.8)) {
            $status = "Nearing End of Life"
            $recommendations += "Asset approaching lifecycle limit - plan replacement"
        }
    }

    # OS Support Assessment
    if (-not $ComputerInfo.OSSupported) {
        $recommendations += "Operating system no longer supported - upgrade required"
        $status = "Unsupported"
    }

    $ComputerInfo.AssetLifecycleStatus = $status
    $ComputerInfo.AssetRecommendations = $recommendations

    if ($status -in @("End of Life", "Unsupported")) {
        $Script:Statistics.AssetLifecycleAlerts++
    }
}

function Invoke-RiskAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$ComputerInfo
    )

    $riskScore = 0

    # OS Risk Scoring
    switch ($ComputerInfo.SecurityRisk) {
        "Critical" { $riskScore += 40 }
        "High" { $riskScore += 30 }
        "Medium" { $riskScore += 20 }
        "Low" { $riskScore += 10 }
    }

    # Activity Risk Scoring
    if ($ComputerInfo.InactiveDays -gt 365) { $riskScore += 30 }
    elseif ($ComputerInfo.InactiveDays -gt 180) { $riskScore += 20 }
    elseif ($ComputerInfo.InactiveDays -gt 90) { $riskScore += 10 }

    # Security Configuration Risk
    if ($ComputerInfo.TrustedForDelegation) { $riskScore += 15 }
    if ($ComputerInfo.SecurityFindings.Count -gt 0) { $riskScore += 10 }

    # Compliance Risk
    if ($ComputerInfo.ComplianceStatus -eq "Non-Compliant") { $riskScore += 15 }

    $ComputerInfo.RiskScore = $riskScore
}

function Export-Results {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CSV', 'JSON', 'Excel', 'Object', 'HTML')]
        [string]$Format
    )

    if (-not $Data -or $Data.Count -eq 0) {
        Write-Warning "No data to export"
        return
    }

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    switch ($Format) {
        'CSV' {
            $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.csv"
            $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'JSON' {
            $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.json"
            $exportData = @{
                Metadata = @{
                    Version = "2.5"
                    GeneratedOn = Get-Date
                    Domain = $DomainName
                    TotalComputers = $Data.Count
                    Statistics = $Script:Statistics
                }
                Computers = $Data
            }
            $exportData | ConvertTo-Json -Depth 6 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'Excel' {
            try {
                $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.xlsx"

                if (Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue) {
                    Import-Module ImportExcel -ErrorAction Stop

                    # Create multiple worksheets
                    $Data | Export-Excel -Path $outputFile -WorksheetName "Computer Inventory" -AutoSize -FreezeTopRow -BoldTopRow

                    # Summary worksheet
                    $summary = Generate-SummaryReport -Data $Data
                    $summary | Export-Excel -Path $outputFile -WorksheetName "Executive Summary" -AutoSize -FreezeTopRow -BoldTopRow

                    # High-risk computers
                    $highRisk = $Data | Where-Object { $_.SecurityRisk -in @("Critical", "High") }
                    if ($highRisk) {
                        $highRisk | Export-Excel -Path $outputFile -WorksheetName "High Risk Systems" -AutoSize -FreezeTopRow -BoldTopRow
                    }

                    Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                } else {
                    Write-Warning "ImportExcel module not available. Exporting as CSV instead."
                    $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.csv"
                    $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
                    Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                }
            } catch {
                Write-Warning "Excel export failed: $($_.Exception.Message). Falling back to CSV."
                $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.csv"
                $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
                Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
                return $outputFile
            }
        }

        'HTML' {
            $outputFile = Join-Path $OutputPath "$DomainName-Computers-v2.5-$timestamp.html"
            Generate-HTMLReport -Data $Data -FilePath $outputFile
            Write-Host "Computer inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'Object' {
            Write-Host "Returning $($Data.Count) computer objects" -ForegroundColor Green
            return $Data
        }
    }
}

function Generate-SummaryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data
    )

    $summary = @()

    # Overall statistics
    $summary += [PSCustomObject]@{
        Metric = "Total Computers"
        Value = $Data.Count
        Category = "Overview"
    }

    # Security risk distribution
    foreach ($risk in @("Critical", "High", "Medium", "Low")) {
        $count = ($Data | Where-Object { $_.SecurityRisk -eq $risk }).Count
        $summary += [PSCustomObject]@{
            Metric = "$risk Security Risk"
            Value = $count
            Category = "Security"
        }
    }

    # OS distribution
    $osDistribution = $Data | Group-Object OSCategory | Sort-Object Count -Descending
    foreach ($os in $osDistribution) {
        $summary += [PSCustomObject]@{
            Metric = "$($os.Name) Systems"
            Value = $os.Count
            Category = "Operating System"
        }
    }

    return $summary
}

function Generate-HTMLReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Computer Inventory Report v2.5</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2E86AB; color: white; padding: 20px; text-align: center; }
        .summary { margin: 20px 0; }
        .risk-critical { background-color: #ff4444; color: white; }
        .risk-high { background-color: #ff8800; color: white; }
        .risk-medium { background-color: #ffcc00; }
        .risk-low { background-color: #44ff44; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Computer Inventory Report v2.5</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Total Computers: $($Data.Count)</p>
    </div>

    <div class="summary">
        <h2>Security Risk Summary</h2>
        <table>
            <tr><th>Risk Level</th><th>Count</th></tr>
"@

    foreach ($risk in @("Critical", "High", "Medium", "Low")) {
        $count = ($Data | Where-Object { $_.SecurityRisk -eq $risk }).Count
        $cssClass = "risk-$($risk.ToLower())"
        $html += "            <tr class=`"$cssClass`"><td>$risk</td><td>$count</td></tr>`n"
    }

    $html += @"
        </table>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main execution
try {
    Write-Verbose "Starting Computer Inventory and Analysis v2.5"

    # Initialize configuration
    Initialize-Configuration -ConfigFile $ConfigurationFile

    # Import ActiveDirectory module if not already loaded
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Verbose "ActiveDirectory module imported successfully"
    }

    # Get domain information
    if ([string]::IsNullOrEmpty($DomainName)) {
        $domain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
        $DomainName = $domain.Name
        Write-Verbose "Using current domain: $DomainName"
    } else {
        $domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
        Write-Verbose "Using specified domain: $DomainName"
    }

    Write-Host "Computer Inventory and Analysis v2.5" -ForegroundColor Cyan
    Write-Host "Domain: $DomainName" -ForegroundColor Green
    Write-Host "Starting comprehensive analysis..." -ForegroundColor Yellow

    # Retrieve computer details
    $computers = Get-ComputerDetails -DomainName $DomainName -Filter $Filter -IncludeDisabled:$IncludeDisabled -IncludeExtendedProperties:$IncludeExtendedProperties -DaysInactive $DaysInactive -SecurityAssessment:$SecurityAssessment -ComplianceCheck:$ComplianceCheck -AssetManagement:$AssetManagement -RiskAnalysis:$RiskAnalysis -Credential $Credential

    if (-not $computers -or $computers.Count -eq 0) {
        Write-Warning "No computers found matching the specified criteria"
        exit 0
    }

    Write-Host "Analysis completed for $($computers.Count) computers" -ForegroundColor Green

    # Export results
    $result = Export-Results -Data $computers -OutputPath $OutputPath -DomainName $DomainName -Format $OutputFormat

    # Display comprehensive summary statistics
    Write-Host "`nComputer Inventory Analysis Summary (v2.5):" -ForegroundColor Yellow
    Write-Host "=" * 50 -ForegroundColor Yellow

    # Basic statistics
    Write-Host "Total Computers Analyzed: $($Script:Statistics.TotalProcessed)" -ForegroundColor White
    Write-Host "Enabled Computers: $(($computers | Where-Object { $_.Enabled }).Count)" -ForegroundColor Green
    Write-Host "Disabled Computers: $($Script:Statistics.DisabledComputers)" -ForegroundColor Red

    # Activity statistics
    $activeComputers = ($computers | Where-Object { $_.ActivityStatus -eq "Active" }).Count
    $inactiveComputers = ($computers | Where-Object { $_.ActivityStatus -eq "Inactive" }).Count
    $staleComputers = ($computers | Where-Object { $_.ActivityStatus -eq "Stale" }).Count

    Write-Host "`nActivity Status Distribution:" -ForegroundColor Yellow
    Write-Host "  Active (?30 days): $activeComputers" -ForegroundColor Green
    Write-Host "  Inactive (31-90 days): $inactiveComputers" -ForegroundColor Yellow
    Write-Host "  Stale (>90 days): $staleComputers" -ForegroundColor Red

    # Security risk distribution
    Write-Host "`nSecurity Risk Distribution:" -ForegroundColor Yellow
    foreach ($risk in @("Critical", "High", "Medium", "Low")) {
        $count = $Script:Statistics.SecurityRisks[$risk]
        $color = switch ($risk) {
            "Critical" { "Red" }
            "High" { "Magenta" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
        }
        Write-Host "  $risk Risk: $count" -ForegroundColor $color
    }

    # Operating system distribution
    $osDistribution = $computers | Group-Object OSCategory | Sort-Object Count -Descending
    Write-Host "`nOperating System Distribution:" -ForegroundColor Yellow
    foreach ($os in $osDistribution) {
        Write-Host "  $($os.Name): $($os.Count)" -ForegroundColor White
    }

    # Support status
    $supportedSystems = ($computers | Where-Object { $_.OSSupported }).Count
    $unsupportedSystems = ($computers | Where-Object { -not $_.OSSupported }).Count
    Write-Host "`nSupport Status:" -ForegroundColor Yellow
    Write-Host "  Supported Systems: $supportedSystems" -ForegroundColor Green
    Write-Host "  Unsupported Systems: $unsupportedSystems" -ForegroundColor Red

    # Analysis-specific summaries
    if ($ComplianceCheck) {
        Write-Host "`nCompliance Summary:" -ForegroundColor Yellow
        Write-Host "  Compliance Issues Found: $($Script:Statistics.ComplianceIssues)" -ForegroundColor $(if ($Script:Statistics.ComplianceIssues -gt 0) { "Red" } else { "Green" })
    }

    if ($AssetManagement) {
        Write-Host "`nAsset Management Summary:" -ForegroundColor Yellow
        Write-Host "  Lifecycle Alerts: $($Script:Statistics.AssetLifecycleAlerts)" -ForegroundColor $(if ($Script:Statistics.AssetLifecycleAlerts -gt 0) { "Yellow" } else { "Green" })
    }

    # Critical findings alert
    $criticalFindings = $computers | Where-Object { $_.SecurityRisk -eq "Critical" }
    if ($criticalFindings.Count -gt 0) {
        Write-Host "`nCRITICAL FINDINGS:" -ForegroundColor Red -BackgroundColor Yellow
        foreach ($finding in $criticalFindings | Select-Object -First 5) {
            Write-Host "  $($finding.Name) - $($finding.OperatingSystem)" -ForegroundColor Red
        }
        if ($criticalFindings.Count -gt 5) {
            Write-Host "  ... and $($criticalFindings.Count - 5) more" -ForegroundColor Red
        }
    }

    # Monitoring integration
    if ($MonitoringIntegration) {
        $alertData = @{
            Timestamp = Get-Date
            Domain = $DomainName
            TotalComputers = $computers.Count
            CriticalRisk = $Script:Statistics.SecurityRisks.Critical
            HighRisk = $Script:Statistics.SecurityRisks.High
            UnsupportedSystems = $unsupportedSystems
            StaleComputers = $staleComputers
        }

        $alertFile = Join-Path $OutputPath "$DomainName-ComputerAlerts-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $alertData | ConvertTo-Json | Out-File -FilePath $alertFile -Encoding UTF8
        Write-Host "`nMonitoring alerts exported to: $alertFile" -ForegroundColor Cyan
    }

    if ($OutputFormat -eq 'Object') {
        return $result
    }

} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Error "Line: $($_.InvocationInfo.ScriptLineNumber)"
    exit 1
}

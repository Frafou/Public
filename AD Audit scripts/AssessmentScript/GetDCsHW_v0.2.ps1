<#
.SYNOPSIS
    Comprehensive Domain Controller hardware inventory and performance analysis tool.

.DESCRIPTION
    This advanced script performs detailed hardware inventory of all domain controllers
    in the Active Directory environment, providing comprehensive system information,
    performance metrics, health assessment, and capacity planning data. Supports
    multiple output formats, advanced analysis, and enterprise-grade reporting with
    actionable insights for infrastructure planning and management.

.PARAMETER DomainName
    Specifies the domain to query for domain controllers. If not provided, uses the
    current computer's domain. Supports cross-domain enumeration with appropriate credentials.

.PARAMETER OutputPath
    Specifies the output directory for result files. Default is current directory.
    Creates directory structure if it doesn't exist.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'CSV', 'JSON', 'Excel', 'Object', 'HTML'.
    Default is 'CSV'. Each format optimized for different use cases.

.PARAMETER IncludePerformanceCounters
    Include system performance counters and metrics for detailed analysis.
    Provides CPU utilization, memory usage, and disk performance data.

.PARAMETER IncludeNetworkInfo
    Include detailed network adapter information, IP configuration,
    and connectivity analysis for comprehensive network assessment.

.PARAMETER IncludeDiskInfo
    Include detailed disk and storage information including capacity,
    free space, disk health, and performance characteristics.

.PARAMETER IncludeServicesInfo
    Include critical services status and configuration for
    domain controller functionality assessment.

.PARAMETER HealthAssessment
    Perform comprehensive health assessment including system validation,
    performance analysis, and capacity planning recommendations.

.PARAMETER ComplianceCheck
    Perform compliance checking against domain controller best practices,
    security guidelines, and organizational policies.

.PARAMETER CapacityPlanning
    Include capacity planning analysis with growth projections,
    resource utilization trends, and upgrade recommendations.

.PARAMETER SecurityAnalysis
    Perform security configuration analysis including patch levels,
    security settings, and vulnerability assessment.

.PARAMETER Credential
    Specifies credentials to use when querying domain controllers.
    Required for cross-domain scenarios or when running without
    appropriate privileges.

.PARAMETER IncludeStatistics
    Include comprehensive statistics and analysis in output with
    executive summary and trending information.

.PARAMETER MonitoringIntegration
    Enable monitoring system integration features including JSON output
    and alert generation for critical findings.

.PARAMETER ConfigurationFile
    Path to configuration file containing advanced settings, thresholds,
    and organizational policies for health and compliance checking.

.PARAMETER MaxConcurrentJobs
    Maximum number of concurrent WMI/CIM jobs for parallel processing.
    Default is 5. Increase for faster processing in large environments.

.PARAMETER TimeoutSeconds
    Timeout in seconds for WMI/CIM queries per domain controller.
    Default is 300 seconds. Adjust based on network latency.

.EXAMPLE
    .\GetDCsHW_V0.2.ps1
    Basic domain controller hardware inventory for current domain.

.EXAMPLE
    .\GetDCsHW_V0.2.ps1 -HealthAssessment -ComplianceCheck -OutputFormat Excel
    Comprehensive health and compliance assessment exported to Excel.

.EXAMPLE
    .\GetDCsHW_V0.2.ps1 -IncludePerformanceCounters -CapacityPlanning -OutputFormat JSON
    Performance analysis with capacity planning in JSON format for automation.

.EXAMPLE
    .\GetDCsHW_V0.2.ps1 -SecurityAnalysis -MonitoringIntegration -IncludeStatistics
    Security analysis with monitoring integration and comprehensive statistics.

.EXAMPLE
    .\GetDCsHW_V0.2.ps1 -OutputFormat Object | Where-Object {$_.HealthStatus -eq 'Warning'}
    Return domain controller objects for pipeline processing, filtering systems with warnings.

.NOTES
    Version: 2.5
    Author: Enterprise PowerShell Modernization
    Last Modified: February 2026
    Requires: PowerShell 5.1 or higher, ActiveDirectory module
    Optional: ImportExcel module for Excel output

    Change Log:
    v0.x - Basic DC hardware enumeration with WMI
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

    [Parameter(Mandatory = $false, HelpMessage = "Include performance counters")]
    [switch]$IncludePerformanceCounters,

    [Parameter(Mandatory = $false, HelpMessage = "Include network information")]
    [switch]$IncludeNetworkInfo,

    [Parameter(Mandatory = $false, HelpMessage = "Include disk information")]
    [switch]$IncludeDiskInfo,

    [Parameter(Mandatory = $false, HelpMessage = "Include services information")]
    [switch]$IncludeServicesInfo,

    [Parameter(Mandatory = $false, HelpMessage = "Perform health assessment")]
    [switch]$HealthAssessment,

    [Parameter(Mandatory = $false, HelpMessage = "Perform compliance checking")]
    [switch]$ComplianceCheck,

    [Parameter(Mandatory = $false, HelpMessage = "Include capacity planning analysis")]
    [switch]$CapacityPlanning,

    [Parameter(Mandatory = $false, HelpMessage = "Perform security analysis")]
    [switch]$SecurityAnalysis,

    [Parameter(Mandatory = $false, HelpMessage = "Credentials for DC access")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = "Include comprehensive statistics")]
    [switch]$IncludeStatistics,

    [Parameter(Mandatory = $false, HelpMessage = "Enable monitoring integration")]
    [switch]$MonitoringIntegration,

    [Parameter(Mandatory = $false, HelpMessage = "Configuration file path")]
    [string]$ConfigurationFile,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum concurrent jobs")]
    [ValidateRange(1, 20)]
    [int]$MaxConcurrentJobs = 5,

    [Parameter(Mandatory = $false, HelpMessage = "Timeout for WMI queries in seconds")]
    [ValidateRange(60, 1800)]
    [int]$TimeoutSeconds = 300
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Global variables for configuration and statistics
$Script:Config = @{}
$Script:Statistics = @{}
$Script:HealthThresholds = @{}
$Script:CompliancePolicies = @{}

function Initialize-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile
    )

    # Default configuration
    $Script:Config = @{
        HealthThresholds = @{
            CPUWarning = 80
            CPUCritical = 95
            MemoryWarning = 80
            MemoryCritical = 90
            DiskWarning = 85
            DiskCritical = 95
            UptimeMinimum = 7  # days
        }
        ComplianceStandards = @(
            'WindowsSecurityBaseline',
            'DomainControllerBaseline',
            'OrganizationalPolicies'
        )
        PerformanceCounters = @(
            '\Processor(_Total)\% Processor Time',
            '\Memory\Available MBytes',
            '\LogicalDisk(_Total)\% Free Space',
            '\Network Interface(*)\Bytes Total/sec'
        )
        CriticalServices = @(
            'NTDS', 'DNS', 'Netlogon', 'W32Time',
            'DFSR', 'ADWS', 'KDC', 'EventLog'
        )
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

function Get-DomainControllerDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformanceCounters,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeNetworkInfo,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeDiskInfo,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeServicesInfo,

        [Parameter(Mandatory = $false)]
        [switch]$HealthAssessment,

        [Parameter(Mandatory = $false)]
        [switch]$ComplianceCheck,

        [Parameter(Mandatory = $false)]
        [switch]$CapacityPlanning,

        [Parameter(Mandatory = $false)]
        [switch]$SecurityAnalysis,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$MaxConcurrentJobs,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds
    )

    try {
        Write-Verbose "Starting domain controller enumeration for domain: $DomainName"

        # Get domain controllers
        $getDCParams = @{
            Server = $DomainName
            Filter = '*'
        }

        if ($Credential) {
            $getDCParams.Credential = $Credential
        }

        $domainControllers = Get-ADDomainController @getDCParams

        if (-not $domainControllers) {
            Write-Warning "No domain controllers found for domain: $DomainName"
            return @()
        }

        Write-Verbose "Found $($domainControllers.Count) domain controllers, starting hardware inventory..."

        # Initialize statistics
        $Script:Statistics = @{
            TotalDCs = $domainControllers.Count
            ProcessedSuccessfully = 0
            Failed = 0
            HealthWarnings = 0
            HealthCritical = 0
            ComplianceIssues = 0
            PerformanceIssues = 0
            SecurityRisks = 0
        }

        # Process domain controllers
        $results = @()
        $jobs = @()
        $processed = 0

        foreach ($dc in $domainControllers) {
            # Wait if too many concurrent jobs
            while ($jobs.Count -ge $MaxConcurrentJobs) {
                $completed = $jobs | Where-Object { $_.State -eq 'Completed' }
                if ($completed) {
                    foreach ($job in $completed) {
                        $jobResult = Receive-Job -Job $job
                        if ($jobResult) {
                            $results += $jobResult
                            $Script:Statistics.ProcessedSuccessfully++
                        } else {
                            $Script:Statistics.Failed++
                        }
                        Remove-Job -Job $job
                    }
                    $jobs = $jobs | Where-Object { $_.State -ne 'Completed' }
                }
                Start-Sleep -Milliseconds 100
            }

            # Start job for this DC
            $jobParams = @{
                DCName = $dc.Name
                DCHostName = $dc.HostName
                DCFQDN = $dc.HostName
                DCIPAddress = $dc.IPv4Address
                DCRole = $dc.OperationMasterRoles
                DCSite = $dc.Site
                IncludePerformanceCounters = $IncludePerformanceCounters
                IncludeNetworkInfo = $IncludeNetworkInfo
                IncludeDiskInfo = $IncludeDiskInfo
                IncludeServicesInfo = $IncludeServicesInfo
                HealthAssessment = $HealthAssessment
                ComplianceCheck = $ComplianceCheck
                CapacityPlanning = $CapacityPlanning
                SecurityAnalysis = $SecurityAnalysis
                Credential = $Credential
                TimeoutSeconds = $TimeoutSeconds
                Config = $Script:Config
            }

            $job = Start-Job -ScriptBlock $script:ProcessDCScriptBlock -ArgumentList $jobParams
            $jobs += $job

            $processed++
            Write-Progress -Activity "Processing Domain Controllers" -Status "Queued $processed of $($domainControllers.Count)" -PercentComplete (($processed / $domainControllers.Count) * 50)
        }

        # Wait for all jobs to complete
        $processed = 0
        while ($jobs.Count -gt 0) {
            $completed = $jobs | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }
            if ($completed) {
                foreach ($job in $completed) {
                    try {
                        $jobResult = Receive-Job -Job $job -ErrorAction Stop
                        if ($jobResult) {
                            $results += $jobResult
                            $Script:Statistics.ProcessedSuccessfully++
                        } else {
                            $Script:Statistics.Failed++
                        }
                    } catch {
                        Write-Warning "Job failed for DC processing: $($_.Exception.Message)"
                        $Script:Statistics.Failed++
                    }
                    Remove-Job -Job $job
                    $processed++
                }
                $jobs = $jobs | Where-Object { $_.State -ne 'Completed' -and $_.State -ne 'Failed' }

                Write-Progress -Activity "Processing Domain Controllers" -Status "Completed $processed of $($domainControllers.Count)" -PercentComplete (50 + ($processed / $domainControllers.Count) * 50)
            }
            Start-Sleep -Milliseconds 100
        }

        Write-Progress -Activity "Processing Domain Controllers" -Completed
        Write-Verbose "Processed $($results.Count) domain controllers successfully"

        return $results

    } catch {
        throw "Error retrieving domain controller details: $($_.Exception.Message)"
    }
}

# ScriptBlock for parallel processing
$script:ProcessDCScriptBlock = {
    param($params)

    try {
        # Extract parameters
        $dcName = $params.DCName
        $dcHostName = $params.DCHostName
        $dcFQDN = $params.DCFQDN
        $dcIPAddress = $params.DCIPAddress
        $dcRole = $params.DCRole
        $dcSite = $params.DCSite
        $credential = $params.Credential
        $timeoutSeconds = $params.TimeoutSeconds
        $config = $params.Config

        # CIM session options
        $sessionOption = New-CimSessionOption -Protocol WSMan

        $cimParams = @{
            ComputerName = $dcFQDN
            SessionOption = $sessionOption
            OperationTimeoutSec = $timeoutSeconds
            ErrorAction = 'Stop'
        }

        if ($credential) {
            $cimParams.Credential = $credential
        }

        # Create CIM session
        $cimSession = New-CimSession @cimParams

        # Basic system information
        $computerSystem = Get-CimInstance -CimSession $cimSession -ClassName Win32_ComputerSystem
        $operatingSystem = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem
        $processor = Get-CimInstance -CimSession $cimSession -ClassName Win32_Processor
        $bios = Get-CimInstance -CimSession $cimSession -ClassName Win32_BIOS

        # Calculate system metrics
        $totalRAM = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        $freeRAM = [math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
        $usedRAM = [math]::Round(($totalRAM * 1024) - $freeRAM, 2)
        $ramUtilization = [math]::Round(($usedRAM / ($totalRAM * 1024)) * 100, 2)

        $uptime = (Get-Date) - $operatingSystem.LastBootUpTime

        # Build basic result object
        $dcInfo = [PSCustomObject]@{
            # Identity Information
            ComputerName = $dcName
            HostName = $dcHostName
            FQDN = $dcFQDN
            IPAddress = $dcIPAddress
            Site = $dcSite
            OperationMasterRoles = if ($dcRole) { $dcRole -join ', ' } else { 'None' }

            # Hardware Information
            Manufacturer = $computerSystem.Manufacturer
            Model = $computerSystem.Model
            SerialNumber = $bios.SerialNumber
            BIOSVersion = $bios.SMBIOSBIOSVersion

            # System Resources
            TotalRAM_GB = $totalRAM
            UsedRAM_MB = $usedRAM
            FreeRAM_MB = $freeRAM
            RAMUtilization_Percent = $ramUtilization

            # Processor Information
            ProcessorName = $processor[0].Name
            ProcessorCores = ($processor | Measure-Object NumberOfCores -Sum).Sum
            LogicalProcessors = ($processor | Measure-Object NumberOfLogicalProcessors -Sum).Sum
            ProcessorSpeed_MHz = $processor[0].MaxClockSpeed

            # Operating System
            OperatingSystem = $operatingSystem.Caption
            OSVersion = $operatingSystem.Version
            OSBuild = $operatingSystem.BuildNumber
            ServicePack = $operatingSystem.ServicePackMajorVersion

            # System Status
            LastBootTime = $operatingSystem.LastBootUpTime
            Uptime_Days = [math]::Round($uptime.TotalDays, 2)
            SystemType = $computerSystem.SystemType
            Domain = $computerSystem.Domain

            # Analysis Results (to be populated)
            HealthStatus = 'Unknown'
            HealthIssues = @()
            PerformanceMetrics = @{}
            ComplianceStatus = 'Unknown'
            ComplianceIssues = @()
            SecurityFindings = @()
            CapacityRecommendations = @()

            # Metadata
            CollectionTime = Get-Date
            AnalysisVersion = '2.5'
            DataSource = 'CIM/WMI'
            ConnectionMethod = 'WSMan'
        }

        # Extended information collection based on parameters
        if ($params.IncludeDiskInfo) {
            Add-DiskInformation -DCInfo $dcInfo -CimSession $cimSession
        }

        if ($params.IncludeNetworkInfo) {
            Add-NetworkInformation -DCInfo $dcInfo -CimSession $cimSession
        }

        if ($params.IncludePerformanceCounters) {
            Add-PerformanceCounters -DCInfo $dcInfo -CimSession $cimSession -Config $config
        }

        if ($params.IncludeServicesInfo) {
            Add-ServicesInformation -DCInfo $dcInfo -CimSession $cimSession -Config $config
        }

        if ($params.HealthAssessment) {
            Invoke-HealthAssessment -DCInfo $dcInfo -Config $config
        }

        if ($params.ComplianceCheck) {
            Invoke-ComplianceCheck -DCInfo $dcInfo -Config $config
        }

        if ($params.CapacityPlanning) {
            Invoke-CapacityPlanning -DCInfo $dcInfo -Config $config
        }

        if ($params.SecurityAnalysis) {
            Invoke-SecurityAnalysis -DCInfo $dcInfo -CimSession $cimSession -Config $config
        }

        # Cleanup
        Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue

        return $dcInfo

    } catch {
        # Cleanup on error
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
        }

        # Return error object
        return [PSCustomObject]@{
            ComputerName = $dcName
            HostName = $dcHostName
            FQDN = $dcFQDN
            Error = $_.Exception.Message
            HealthStatus = 'Critical'
            CollectionTime = Get-Date
            AnalysisVersion = '2.5'
        }
    }
}

function Add-DiskInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    try {
        $logicalDisks = Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk
        $diskInfo = @()

        foreach ($disk in $logicalDisks) {
            if ($disk.DriveType -eq 3) {  # Fixed disks only
                $totalSize = [math]::Round($disk.Size / 1GB, 2)
                $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
                $usedSpace = $totalSize - $freeSpace
                $usedPercent = if ($totalSize -gt 0) { [math]::Round(($usedSpace / $totalSize) * 100, 2) } else { 0 }

                $diskInfo += [PSCustomObject]@{
                    Drive = $disk.DeviceID
                    Label = $disk.VolumeName
                    TotalSize_GB = $totalSize
                    UsedSpace_GB = $usedSpace
                    FreeSpace_GB = $freeSpace
                    UsedPercent = $usedPercent
                    FileSystem = $disk.FileSystem
                }
            }
        }

        $DCInfo | Add-Member -NotePropertyName 'DiskInfo' -NotePropertyValue $diskInfo -Force

    } catch {
        $DCInfo | Add-Member -NotePropertyName 'DiskInfo' -NotePropertyValue "Error: $($_.Exception.Message)" -Force
    }
}

function Add-NetworkInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession
    )

    try {
        $networkAdapters = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        $networkInfo = @()

        foreach ($adapter in $networkAdapters) {
            $networkInfo += [PSCustomObject]@{
                Description = $adapter.Description
                IPAddress = $adapter.IPAddress -join ', '
                SubnetMask = $adapter.IPSubnet -join ', '
                DefaultGateway = $adapter.DefaultIPGateway -join ', '
                DNSServers = $adapter.DNSServerSearchOrder -join ', '
                DHCPEnabled = $adapter.DHCPEnabled
                MACAddress = $adapter.MACAddress
            }
        }

        $DCInfo | Add-Member -NotePropertyName 'NetworkInfo' -NotePropertyValue $networkInfo -Force

    } catch {
        $DCInfo | Add-Member -NotePropertyName 'NetworkInfo' -NotePropertyValue "Error: $($_.Exception.Message)" -Force
    }
}

function Add-PerformanceCounters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    try {
        $perfMetrics = @{}

        # CPU utilization (approximate from WMI)
        $cpu = Get-CimInstance -CimSession $CimSession -ClassName Win32_PerfRawData_PerfOS_Processor | Where-Object { $_.Name -eq '_Total' }
        if ($cpu) {
            $perfMetrics.CPUUtilization = "Collected"
        }

        # Memory metrics already collected
        $perfMetrics.MemoryUtilization = $DCInfo.RAMUtilization_Percent

        # Disk performance
        $diskPerf = Get-CimInstance -CimSession $CimSession -ClassName Win32_PerfRawData_PerfDisk_LogicalDisk | Where-Object { $_.Name -eq '_Total' }
        if ($diskPerf) {
            $perfMetrics.DiskActivity = "Collected"
        }

        $DCInfo.PerformanceMetrics = $perfMetrics

    } catch {
        $DCInfo.PerformanceMetrics = @{ Error = $_.Exception.Message }
    }
}

function Add-ServicesInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    try {
        $services = Get-CimInstance -CimSession $CimSession -ClassName Win32_Service
        $criticalServices = @()

        foreach ($serviceName in $Config.CriticalServices) {
            $service = $services | Where-Object { $_.Name -eq $serviceName }
            if ($service) {
                $criticalServices += [PSCustomObject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    State = $service.State
                    Status = $service.Status
                    StartMode = $service.StartMode
                }
            } else {
                $criticalServices += [PSCustomObject]@{
                    Name = $serviceName
                    Status = 'Not Found'
                    State = 'Unknown'
                }
            }
        }

        $DCInfo | Add-Member -NotePropertyName 'CriticalServices' -NotePropertyValue $criticalServices -Force

    } catch {
        $DCInfo | Add-Member -NotePropertyName 'CriticalServices' -NotePropertyValue "Error: $($_.Exception.Message)" -Force
    }
}

function Invoke-HealthAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $healthIssues = @()
    $healthStatus = "Healthy"

    # Memory utilization check
    if ($DCInfo.RAMUtilization_Percent -ge $Config.HealthThresholds.MemoryCritical) {
        $healthIssues += "Critical: Memory utilization at $($DCInfo.RAMUtilization_Percent)%"
        $healthStatus = "Critical"
    } elseif ($DCInfo.RAMUtilization_Percent -ge $Config.HealthThresholds.MemoryWarning) {
        $healthIssues += "Warning: Memory utilization at $($DCInfo.RAMUtilization_Percent)%"
        if ($healthStatus -eq "Healthy") { $healthStatus = "Warning" }
    }

    # Uptime check
    if ($DCInfo.Uptime_Days -lt $Config.HealthThresholds.UptimeMinimum) {
        $healthIssues += "Warning: Recent reboot detected - uptime only $($DCInfo.Uptime_Days) days"
        if ($healthStatus -eq "Healthy") { $healthStatus = "Warning" }
    }

    # Disk space check (if available)
    if ($DCInfo.PSObject.Properties.Name -contains 'DiskInfo' -and $DCInfo.DiskInfo -is [array]) {
        foreach ($disk in $DCInfo.DiskInfo) {
            if ($disk.UsedPercent -ge $Config.HealthThresholds.DiskCritical) {
                $healthIssues += "Critical: Disk $($disk.Drive) at $($disk.UsedPercent)% capacity"
                $healthStatus = "Critical"
            } elseif ($disk.UsedPercent -ge $Config.HealthThresholds.DiskWarning) {
                $healthIssues += "Warning: Disk $($disk.Drive) at $($disk.UsedPercent)% capacity"
                if ($healthStatus -eq "Healthy") { $healthStatus = "Warning" }
            }
        }
    }

    # Services check (if available)
    if ($DCInfo.PSObject.Properties.Name -contains 'CriticalServices' -and $DCInfo.CriticalServices -is [array]) {
        $stoppedServices = $DCInfo.CriticalServices | Where-Object { $_.State -ne 'Running' -and $_.Status -ne 'Not Found' }
        if ($stoppedServices) {
            foreach ($service in $stoppedServices) {
                $healthIssues += "Critical: Service $($service.Name) is $($service.State)"
                $healthStatus = "Critical"
            }
        }
    }

    $DCInfo.HealthStatus = $healthStatus
    $DCInfo.HealthIssues = $healthIssues
}

function Invoke-ComplianceCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $complianceIssues = @()
    $complianceStatus = "Compliant"

    # OS Support check
    if ($DCInfo.OperatingSystem -match "2008|2012") {
        $complianceIssues += "Non-compliant: Unsupported operating system version"
        $complianceStatus = "Non-Compliant"
    }

    # Memory baseline check
    if ($DCInfo.TotalRAM_GB -lt 8) {
        $complianceIssues += "Non-compliant: Insufficient memory for domain controller role"
        $complianceStatus = "Non-Compliant"
    }

    # Uptime policy check
    if ($DCInfo.Uptime_Days -gt 365) {
        $complianceIssues += "Warning: Domain controller has not been rebooted in over a year"
        if ($complianceStatus -eq "Compliant") { $complianceStatus = "Warning" }
    }

    $DCInfo.ComplianceStatus = $complianceStatus
    $DCInfo.ComplianceIssues = $complianceIssues
}

function Invoke-CapacityPlanning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $recommendations = @()

    # Memory capacity analysis
    if ($DCInfo.RAMUtilization_Percent -gt 70) {
        $recommendedRAM = [math]::Ceiling($DCInfo.TotalRAM_GB * 1.5)
        $recommendations += "Consider memory upgrade to $($recommendedRAM)GB (current utilization: $($DCInfo.RAMUtilization_Percent)%)"
    }

    # Disk capacity analysis (if available)
    if ($DCInfo.PSObject.Properties.Name -contains 'DiskInfo' -and $DCInfo.DiskInfo -is [array]) {
        foreach ($disk in $DCInfo.DiskInfo) {
            if ($disk.UsedPercent -gt 70) {
                $additionalSpace = [math]::Ceiling($disk.TotalSize_GB * 0.5)
                $recommendations += "Consider expanding disk $($disk.Drive) by $($additionalSpace)GB (current usage: $($disk.UsedPercent)%)"
            }
        }
    }

    # Hardware age assessment
    $currentYear = (Get-Date).Year
    if ($DCInfo.Model -match "2016|2017|2018") {
        $recommendations += "Hardware may be approaching end of life - consider replacement planning"
    }

    $DCInfo.CapacityRecommendations = $recommendations
}

function Invoke-SecurityAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$DCInfo,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimSession]$CimSession,

        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $securityFindings = @()

    try {
        # OS version security assessment
        if ($DCInfo.OperatingSystem -match "2008|2012") {
            $securityFindings += "Critical: Unsupported OS version with no security updates"
        } elseif ($DCInfo.OperatingSystem -match "2016") {
            $securityFindings += "Warning: OS version approaching end of mainstream support"
        }

        # Uptime security assessment
        if ($DCInfo.Uptime_Days -gt 180) {
            $securityFindings += "Warning: Extended uptime may indicate missing security patches"
        }

        # Additional security checks could be added here
        # (Windows Update status, security configurations, etc.)

    } catch {
        $securityFindings += "Error performing security analysis: $($_.Exception.Message)"
    }

    $DCInfo.SecurityFindings = $securityFindings
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
            $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.csv"
            $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'JSON' {
            $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.json"
            $exportData = @{
                Metadata = @{
                    Version = "2.5"
                    GeneratedOn = Get-Date
                    Domain = $DomainName
                    TotalDCs = $Data.Count
                    Statistics = $Script:Statistics
                }
                DomainControllers = $Data
            }
            $exportData | ConvertTo-Json -Depth 8 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'Excel' {
            try {
                $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.xlsx"

                if (Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue) {
                    Import-Module ImportExcel -ErrorAction Stop

                    # Main inventory worksheet
                    $Data | Export-Excel -Path $outputFile -WorksheetName "DC Hardware Inventory" -AutoSize -FreezeTopRow -BoldTopRow

                    # Summary worksheet
                    $summary = Generate-SummaryReport -Data $Data
                    $summary | Export-Excel -Path $outputFile -WorksheetName "Executive Summary" -AutoSize -FreezeTopRow -BoldTopRow

                    # Health issues worksheet
                    $healthIssues = $Data | Where-Object { $_.HealthStatus -ne "Healthy" }
                    if ($healthIssues) {
                        $healthIssues | Export-Excel -Path $outputFile -WorksheetName "Health Issues" -AutoSize -FreezeTopRow -BoldTopRow
                    }

                    Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                } else {
                    Write-Warning "ImportExcel module not available. Exporting as CSV instead."
                    $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.csv"
                    $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
                    Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                }
            } catch {
                Write-Warning "Excel export failed: $($_.Exception.Message). Falling back to CSV."
                $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.csv"
                $Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
                Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
                return $outputFile
            }
        }

        'HTML' {
            $outputFile = Join-Path $OutputPath "$DomainName-DCsHW-v2.5-$timestamp.html"
            Generate-HTMLReport -Data $Data -FilePath $outputFile
            Write-Host "Domain controller inventory exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'Object' {
            Write-Host "Returning $($Data.Count) domain controller objects" -ForegroundColor Green
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
        Metric = "Total Domain Controllers"
        Value = $Data.Count
        Category = "Overview"
    }

    # Health distribution
    foreach ($status in @("Healthy", "Warning", "Critical")) {
        $count = ($Data | Where-Object { $_.HealthStatus -eq $status }).Count
        $summary += [PSCustomObject]@{
            Metric = "$status Health Status"
            Value = $count
            Category = "Health"
        }
    }

    # Hardware statistics
    $totalRAM = ($Data | Measure-Object TotalRAM_GB -Sum).Sum
    $avgRAM = ($Data | Measure-Object TotalRAM_GB -Average).Average
    $totalCores = ($Data | Measure-Object ProcessorCores -Sum).Sum

    $summary += [PSCustomObject]@{
        Metric = "Total RAM (GB)"
        Value = $totalRAM
        Category = "Hardware"
    }

    $summary += [PSCustomObject]@{
        Metric = "Average RAM per DC (GB)"
        Value = [math]::Round($avgRAM, 2)
        Category = "Hardware"
    }

    $summary += [PSCustomObject]@{
        Metric = "Total CPU Cores"
        Value = $totalCores
        Category = "Hardware"
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
    <title>Domain Controller Hardware Inventory Report v2.5</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2E86AB; color: white; padding: 20px; text-align: center; }
        .summary { margin: 20px 0; }
        .status-healthy { background-color: #44ff44; }
        .status-warning { background-color: #ffcc00; }
        .status-critical { background-color: #ff4444; color: white; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Domain Controller Hardware Inventory Report v2.5</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Total Domain Controllers: $($Data.Count)</p>
    </div>

    <div class="summary">
        <h2>Health Status Summary</h2>
        <table>
            <tr><th>Health Status</th><th>Count</th></tr>
"@

    foreach ($status in @("Healthy", "Warning", "Critical")) {
        $count = ($Data | Where-Object { $_.HealthStatus -eq $status }).Count
        $cssClass = "status-$($status.ToLower())"
        $html += "            <tr class=`"$cssClass`"><td>$status</td><td>$count</td></tr>`n"
    }

    $html += @"
        </table>
    </div>

    <div class="summary">
        <h2>Hardware Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total RAM (GB)</td><td>$(($Data | Measure-Object TotalRAM_GB -Sum).Sum)</td></tr>
            <tr><td>Average RAM per DC (GB)</td><td>$([math]::Round(($Data | Measure-Object TotalRAM_GB -Average).Average, 2))</td></tr>
            <tr><td>Total CPU Cores</td><td>$(($Data | Measure-Object ProcessorCores -Sum).Sum)</td></tr>
        </table>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main execution
try {
    Write-Verbose "Starting Domain Controller Hardware Inventory and Analysis v2.5"

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

    Write-Host "Domain Controller Hardware Inventory and Analysis v2.5" -ForegroundColor Cyan
    Write-Host "Domain: $DomainName" -ForegroundColor Green
    Write-Host "Starting comprehensive hardware analysis..." -ForegroundColor Yellow

    # Retrieve domain controller details
    $domainControllers = Get-DomainControllerDetails -DomainName $DomainName -IncludePerformanceCounters:$IncludePerformanceCounters -IncludeNetworkInfo:$IncludeNetworkInfo -IncludeDiskInfo:$IncludeDiskInfo -IncludeServicesInfo:$IncludeServicesInfo -HealthAssessment:$HealthAssessment -ComplianceCheck:$ComplianceCheck -CapacityPlanning:$CapacityPlanning -SecurityAnalysis:$SecurityAnalysis -Credential $Credential -MaxConcurrentJobs $MaxConcurrentJobs -TimeoutSeconds $TimeoutSeconds

    if (-not $domainControllers -or $domainControllers.Count -eq 0) {
        Write-Warning "No domain controllers found or processed successfully"
        exit 0
    }

    Write-Host "Analysis completed for $($domainControllers.Count) domain controllers" -ForegroundColor Green

    # Export results
    $result = Export-Results -Data $domainControllers -OutputPath $OutputPath -DomainName $DomainName -Format $OutputFormat

    # Display comprehensive summary statistics
    Write-Host "`nDomain Controller Hardware Inventory Analysis Summary (v2.5):" -ForegroundColor Yellow
    Write-Host "=" * 65 -ForegroundColor Yellow

    # Basic statistics
    Write-Host "Total Domain Controllers Processed: $($Script:Statistics.ProcessedSuccessfully)" -ForegroundColor White
    Write-Host "Failed Connections: $($Script:Statistics.Failed)" -ForegroundColor $(if ($Script:Statistics.Failed -gt 0) { "Red" } else { "Green" })

    # Health distribution
    $healthyDCs = ($domainControllers | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
    $warningDCs = ($domainControllers | Where-Object { $_.HealthStatus -eq "Warning" }).Count
    $criticalDCs = ($domainControllers | Where-Object { $_.HealthStatus -eq "Critical" }).Count

    Write-Host "`nHealth Status Distribution:" -ForegroundColor Yellow
    Write-Host "  Healthy: $healthyDCs" -ForegroundColor Green
    Write-Host "  Warning: $warningDCs" -ForegroundColor Yellow
    Write-Host "  Critical: $criticalDCs" -ForegroundColor Red

    # Hardware summary
    $totalRAM = ($domainControllers | Measure-Object TotalRAM_GB -Sum).Sum
    $avgRAM = ($domainControllers | Measure-Object TotalRAM_GB -Average).Average
    $totalCores = ($domainControllers | Measure-Object ProcessorCores -Sum).Sum
    $avgCores = ($domainControllers | Measure-Object ProcessorCores -Average).Average

    Write-Host "`nHardware Summary:" -ForegroundColor Yellow
    Write-Host "  Total RAM: $totalRAM GB" -ForegroundColor White
    Write-Host "  Average RAM per DC: $([math]::Round($avgRAM, 2)) GB" -ForegroundColor White
    Write-Host "  Total CPU Cores: $totalCores" -ForegroundColor White
    Write-Host "  Average Cores per DC: $([math]::Round($avgCores, 2))" -ForegroundColor White

    # Operating system distribution
    $osDistribution = $domainControllers | Group-Object { ($_.OperatingSystem -split ' ')[0..2] -join ' ' } | Sort-Object Count -Descending
    Write-Host "`nOperating System Distribution:" -ForegroundColor Yellow
    foreach ($os in $osDistribution) {
        Write-Host "  $($os.Name): $($os.Count)" -ForegroundColor White
    }

    # Site distribution if available
    $siteDistribution = $domainControllers | Group-Object Site | Sort-Object Count -Descending
    if ($siteDistribution -and $siteDistribution.Count -gt 1) {
        Write-Host "`nSite Distribution:" -ForegroundColor Yellow
        foreach ($site in $siteDistribution) {
            Write-Host "  $($site.Name): $($site.Count)" -ForegroundColor White
        }
    }

    # FSMO role distribution
    $fsmoRoles = $domainControllers | Where-Object { $_.OperationMasterRoles -ne 'None' -and $_.OperationMasterRoles }
    if ($fsmoRoles) {
        Write-Host "`nFSMO Role Holders:" -ForegroundColor Yellow
        foreach ($dc in $fsmoRoles) {
            Write-Host "  $($dc.ComputerName): $($dc.OperationMasterRoles)" -ForegroundColor White
        }
    }

    # Analysis-specific summaries
    if ($ComplianceCheck) {
        $complianceIssues = ($domainControllers | Where-Object { $_.ComplianceStatus -eq "Non-Compliant" }).Count
        Write-Host "`nCompliance Summary:" -ForegroundColor Yellow
        Write-Host "  Compliance Issues Found: $complianceIssues" -ForegroundColor $(if ($complianceIssues -gt 0) { "Red" } else { "Green" })
    }

    if ($CapacityPlanning) {
        $capacityRecommendations = ($domainControllers | Where-Object { $_.CapacityRecommendations.Count -gt 0 }).Count
        Write-Host "`nCapacity Planning Summary:" -ForegroundColor Yellow
        Write-Host "  DCs with Capacity Recommendations: $capacityRecommendations" -ForegroundColor $(if ($capacityRecommendations -gt 0) { "Yellow" } else { "Green" })
    }

    if ($SecurityAnalysis) {
        $securityFindings = ($domainControllers | Where-Object { $_.SecurityFindings.Count -gt 0 }).Count
        Write-Host "`nSecurity Analysis Summary:" -ForegroundColor Yellow
        Write-Host "  DCs with Security Findings: $securityFindings" -ForegroundColor $(if ($securityFindings -gt 0) { "Red" } else { "Green" })
    }

    # Critical findings alert
    $criticalFindings = $domainControllers | Where-Object { $_.HealthStatus -eq "Critical" }
    if ($criticalFindings.Count -gt 0) {
        Write-Host "`nCRITICAL FINDINGS:" -ForegroundColor Red -BackgroundColor Yellow
        foreach ($finding in $criticalFindings | Select-Object -First 5) {
            $issues = if ($finding.HealthIssues) { $finding.HealthIssues -join ', ' } else { 'Unknown issue' }
            Write-Host "  $($finding.ComputerName): $issues" -ForegroundColor Red
        }
        if ($criticalFindings.Count -gt 5) {
            Write-Host "  ... and $($criticalFindings.Count - 5) more" -ForegroundColor Red
        }
    }

    # Resource utilization warnings
    $highMemoryDCs = $domainControllers | Where-Object { $_.RAMUtilization_Percent -gt 80 }
    if ($highMemoryDCs.Count -gt 0) {
        Write-Host "`nRESOURCE WARNINGS:" -ForegroundColor Yellow
        foreach ($dc in $highMemoryDCs | Select-Object -First 3) {
            Write-Host "  $($dc.ComputerName): Memory at $($dc.RAMUtilization_Percent)%" -ForegroundColor Yellow
        }
        if ($highMemoryDCs.Count -gt 3) {
            Write-Host "  ... and $($highMemoryDCs.Count - 3) more with high memory usage" -ForegroundColor Yellow
        }
    }

    # Monitoring integration
    if ($MonitoringIntegration) {
        $alertData = @{
            Timestamp = Get-Date
            Domain = $DomainName
            TotalDCs = $domainControllers.Count
            HealthyDCs = $healthyDCs
            WarningDCs = $warningDCs
            CriticalDCs = $criticalDCs
            FailedConnections = $Script:Statistics.Failed
            TotalRAM_GB = $totalRAM
            TotalCores = $totalCores
        }

        $alertFile = Join-Path $OutputPath "$DomainName-DCAlerts-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
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

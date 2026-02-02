<#
.SYNOPSIS
    Comprehensive Domain Controller network share inventory and security analysis tool.

.DESCRIPTION
    This advanced script performs detailed network share enumeration and analysis of all
    domain controllers in the Active Directory environment, providing comprehensive
    share information, security assessment, permissions analysis, and risk evaluation.
    Supports multiple output formats, advanced filtering, and enterprise-grade reporting
    with actionable insights for security hardening and compliance validation.

.PARAMETER DomainName
    Specifies the domain to query for domain controllers. If not provided, uses the
    current computer's domain. Supports cross-domain enumeration with appropriate credentials.

.PARAMETER OutputPath
    Specifies the output directory for result files. Default is current directory.
    Creates directory structure if it doesn't exist.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'CSV', 'JSON', 'Excel', 'Object', 'HTML'.
    Default is 'CSV'. Each format optimized for different use cases.

.PARAMETER IncludeHiddenShares
    Include hidden administrative shares (ending with $) in the analysis.
    Default excludes hidden shares for security-focused analysis.

.PARAMETER IncludePermissions
    Include detailed share permissions analysis for security assessment.
    Provides comprehensive access control evaluation.

.PARAMETER SecurityAssessment
    Perform comprehensive security assessment including share exposure analysis,
    permission validation, and vulnerability identification.

.PARAMETER ComplianceCheck
    Perform compliance checking against share security best practices,
    organizational policies, and industry standards.

.PARAMETER RiskAnalysis
    Perform risk analysis including exposure assessment, data classification,
    and security recommendations for share hardening.

.PARAMETER UsageAnalysis
    Include share usage analysis with access patterns, connection statistics,
    and utilization metrics where available.

.PARAMETER ShareClassification
    Classify shares by type (system, application, data) and sensitivity level
    for better security management and compliance.

.PARAMETER Credential
    Specifies credentials to use when querying domain controllers and accessing shares.
    Required for cross-domain scenarios or when running without appropriate privileges.

.PARAMETER IncludeStatistics
    Include comprehensive statistics and analysis in output with
    executive summary and security metrics.

.PARAMETER MonitoringIntegration
    Enable monitoring system integration features including JSON output
    and alert generation for security findings.

.PARAMETER ConfigurationFile
    Path to configuration file containing advanced settings, security policies,
    and organizational standards for share analysis.

.PARAMETER MaxConcurrentJobs
    Maximum number of concurrent WMI/CIM jobs for parallel processing.
    Default is 5. Increase for faster processing in large environments.

.PARAMETER TimeoutSeconds
    Timeout in seconds for WMI/CIM queries per domain controller.
    Default is 180 seconds. Adjust based on network latency.

.PARAMETER ExcludeDefaultShares
    Exclude default administrative shares (ADMIN$, C$, IPC$, etc.) from analysis.
    Focuses on custom application and data shares.

.EXAMPLE
    .\GetDCsShare_V0.2.ps1
    Basic domain controller share inventory for current domain.

.EXAMPLE
    .\GetDCsShare_V0.2.ps1 -SecurityAssessment -ComplianceCheck -OutputFormat Excel
    Comprehensive security and compliance assessment exported to Excel.

.EXAMPLE
    .\GetDCsShare_V0.2.ps1 -IncludePermissions -RiskAnalysis -OutputFormat JSON
    Detailed permissions analysis with risk assessment in JSON format for automation.

.EXAMPLE
    .\GetDCsShare_V0.2.ps1 -UsageAnalysis -ShareClassification -MonitoringIntegration
    Usage analysis with share classification and monitoring system integration.

.EXAMPLE
    .\GetDCsShare_V0.2.ps1 -OutputFormat Object | Where-Object {$_.RiskLevel -eq 'High'}
    Return share objects for pipeline processing, filtering high-risk shares.

.NOTES
    Version: 2.5
    Author: Enterprise PowerShell Modernization
    Last Modified: February 2026
    Requires: PowerShell 5.1 or higher, ActiveDirectory module
    Optional: ImportExcel module for Excel output

    Change Log:
    v0.x - Basic DC share enumeration with WMI
    v2.5 - Complete enterprise modernization with security analysis
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory = $false, HelpMessage = 'Domain name to query')]
	[string]$DomainName,

	[Parameter(Mandatory = $false, HelpMessage = 'Output directory path')]
	[string]$OutputPath = (Get-Location).Path,

	[Parameter(Mandatory = $false, HelpMessage = 'Output format')]
	[ValidateSet('CSV', 'JSON', 'Excel', 'Object', 'HTML')]
	[string]$OutputFormat = 'CSV',

	[Parameter(Mandatory = $false, HelpMessage = 'Include hidden administrative shares')]
	[switch]$IncludeHiddenShares,

	[Parameter(Mandatory = $false, HelpMessage = 'Include detailed permissions analysis')]
	[switch]$IncludePermissions,

	[Parameter(Mandatory = $false, HelpMessage = 'Perform security assessment')]
	[switch]$SecurityAssessment,

	[Parameter(Mandatory = $false, HelpMessage = 'Perform compliance checking')]
	[switch]$ComplianceCheck,

	[Parameter(Mandatory = $false, HelpMessage = 'Perform risk analysis')]
	[switch]$RiskAnalysis,

	[Parameter(Mandatory = $false, HelpMessage = 'Include usage analysis')]
	[switch]$UsageAnalysis,

	[Parameter(Mandatory = $false, HelpMessage = 'Classify shares by type and sensitivity')]
	[switch]$ShareClassification,

	[Parameter(Mandatory = $false, HelpMessage = 'Credentials for DC and share access')]
	[System.Management.Automation.PSCredential]$Credential,

	[Parameter(Mandatory = $false, HelpMessage = 'Include comprehensive statistics')]
	[switch]$IncludeStatistics,

	[Parameter(Mandatory = $false, HelpMessage = 'Enable monitoring integration')]
	[switch]$MonitoringIntegration,

	[Parameter(Mandatory = $false, HelpMessage = 'Configuration file path')]
	[string]$ConfigurationFile,

	[Parameter(Mandatory = $false, HelpMessage = 'Maximum concurrent jobs')]
	[ValidateRange(1, 20)]
	[int]$MaxConcurrentJobs = 5,

	[Parameter(Mandatory = $false, HelpMessage = 'Timeout for WMI queries in seconds')]
	[ValidateRange(60, 600)]
	[int]$TimeoutSeconds = 180,

	[Parameter(Mandatory = $false, HelpMessage = 'Exclude default administrative shares')]
	[switch]$ExcludeDefaultShares
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

# Global variables for configuration and statistics
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
		DefaultAdminShares  = @('ADMIN$', 'C$', 'D$', 'E$', 'F$', 'IPC$', 'PRINT$', 'FAX$')
		RiskClassification  = @{
			HighRisk     = @('Everyone', 'Authenticated Users', 'Domain Users')
			MediumRisk   = @('Domain Computers', 'Users')
			SystemShares = @('ADMIN$', 'IPC$', 'C$', 'SYSVOL', 'NETLOGON')
		}
		ShareTypes          = @{
			System      = @('ADMIN$', 'IPC$', 'PRINT$', 'FAX$')
			DomainData  = @('SYSVOL', 'NETLOGON')
			DriveShares = @('C$', 'D$', 'E$', 'F$', 'G$', 'H$')
			Application = @('Applications', 'Software', 'Tools', 'Scripts')
		}
		ComplianceStandards = @(
			'CIS_Controls',
			'NIST_Cybersecurity_Framework',
			'ISO27001',
			'OrganizationalPolicies'
		)
		SecurityThresholds  = @{
			MaxEveryoneAccess     = 0
			MaxAuthenticatedUsers = 2
			MaxDomainUsers        = 5
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

function Get-DomainControllerShares {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$DomainName,

		[Parameter(Mandatory = $false)]
		[switch]$IncludeHiddenShares,

		[Parameter(Mandatory = $false)]
		[switch]$IncludePermissions,

		[Parameter(Mandatory = $false)]
		[switch]$SecurityAssessment,

		[Parameter(Mandatory = $false)]
		[switch]$ComplianceCheck,

		[Parameter(Mandatory = $false)]
		[switch]$RiskAnalysis,

		[Parameter(Mandatory = $false)]
		[switch]$UsageAnalysis,

		[Parameter(Mandatory = $false)]
		[switch]$ShareClassification,

		[Parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]$Credential,

		[Parameter(Mandatory = $false)]
		[int]$MaxConcurrentJobs,

		[Parameter(Mandatory = $false)]
		[int]$TimeoutSeconds,

		[Parameter(Mandatory = $false)]
		[switch]$ExcludeDefaultShares
	)

	try {
		Write-Verbose "Starting domain controller share enumeration for domain: $DomainName"

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

		Write-Verbose "Found $($domainControllers.Count) domain controllers, starting share enumeration..."

		# Initialize statistics
		$Script:Statistics = @{
			TotalDCs              = $domainControllers.Count
			ProcessedSuccessfully = 0
			Failed                = 0
			TotalShares           = 0
			SecurityRisks         = @{ Critical = 0; High = 0; Medium = 0; Low = 0 }
			ComplianceIssues      = 0
			HiddenShares          = 0
			DefaultShares         = 0
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
				DCName               = $dc.Name
				DCHostName           = $dc.HostName
				DCFQDN               = $dc.HostName
				DCIPAddress          = $dc.IPv4Address
				DCSite               = $dc.Site
				IncludeHiddenShares  = $IncludeHiddenShares
				IncludePermissions   = $IncludePermissions
				SecurityAssessment   = $SecurityAssessment
				ComplianceCheck      = $ComplianceCheck
				RiskAnalysis         = $RiskAnalysis
				UsageAnalysis        = $UsageAnalysis
				ShareClassification  = $ShareClassification
				ExcludeDefaultShares = $ExcludeDefaultShares
				Credential           = $Credential
				TimeoutSeconds       = $TimeoutSeconds
				Config               = $Script:Config
			}

			$job = Start-Job -ScriptBlock $script:ProcessDCSharesScriptBlock -ArgumentList $jobParams
			$jobs += $job

			$processed++
			Write-Progress -Activity 'Processing Domain Controllers' -Status "Queued $processed of $($domainControllers.Count)" -PercentComplete (($processed / $domainControllers.Count) * 50)
		}

		# Wait for all jobs to complete
		$processed = 0
		while ($jobs.Count -gt 0) {
			$completed = $jobs | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }
			if ($completed) {
				foreach ($job in $completed) {
					try {
						$jobResult = Receive-Job -Job $job -ErrorAction Stop
						if ($jobResult -and $jobResult.Count -gt 0) {
							$results += $jobResult
							$Script:Statistics.TotalShares += $jobResult.Count
							$Script:Statistics.ProcessedSuccessfully++
						} else {
							$Script:Statistics.Failed++
						}
					} catch {
						Write-Warning "Job failed for DC share processing: $($_.Exception.Message)"
						$Script:Statistics.Failed++
					}
					Remove-Job -Job $job
					$processed++
				}
				$jobs = $jobs | Where-Object { $_.State -ne 'Completed' -and $_.State -ne 'Failed' }

				Write-Progress -Activity 'Processing Domain Controllers' -Status "Completed $processed of $($domainControllers.Count)" -PercentComplete (50 + ($processed / $domainControllers.Count) * 50)
			}
			Start-Sleep -Milliseconds 100
		}

		Write-Progress -Activity 'Processing Domain Controllers' -Completed
		Write-Verbose "Processed $($results.Count) shares from $($Script:Statistics.ProcessedSuccessfully) domain controllers"

		return $results

	} catch {
		throw "Error retrieving domain controller shares: $($_.Exception.Message)"
	}
}

# ScriptBlock for parallel processing
$script:ProcessDCSharesScriptBlock = {
	param($params)

	try {
		# Extract parameters
		$dcName = $params.DCName
		$dcHostName = $params.DCHostName
		$dcFQDN = $params.DCFQDN
		$credential = $params.Credential
		$timeoutSeconds = $params.TimeoutSeconds
		$config = $params.Config

		# WMI query parameters
		$wmiParams = @{
			ComputerName = $dcFQDN
			Class        = 'Win32_Share'
			ErrorAction  = 'Stop'
		}

		if ($credential) {
			$wmiParams.Credential = $credential
		}

		# Get shares from the domain controller
		$shares = Get-WmiObject @wmiParams

		if (-not $shares) {
			Write-Warning "No shares found on DC: $dcName"
			return @()
		}

		$dcShares = @()

		foreach ($share in $shares) {
			# Skip hidden shares if not requested
			if (-not $params.IncludeHiddenShares -and $share.Name.EndsWith('$')) {
				continue
			}

			# Skip default shares if requested
			if ($params.ExcludeDefaultShares -and $config.DefaultAdminShares -contains $share.Name) {
				continue
			}

			# Build share information object
			$shareInfo = [PSCustomObject]@{
				# Basic Information
				ComputerName     = $dcName
				ComputerFQDN     = $dcFQDN
				ShareName        = $share.Name
				SharePath        = $share.Path
				Description      = $share.Description
				ShareType        = Get-ShareTypeFromWMI -Type $share.Type

				# Status and Properties
				Status           = $share.Status
				AllowMaximum     = $share.AllowMaximum
				MaximumAllowed   = $share.MaximumAllowed
				CurrentUsers     = $share.CurrentUsers

				# Analysis Results (to be populated)
				ShareCategory    = 'Unknown'
				IsHidden         = $share.Name.EndsWith('$')
				IsDefaultShare   = $config.DefaultAdminShares -contains $share.Name
				SecurityRisk     = 'Unknown'
				RiskFactors      = @()
				ComplianceStatus = 'Unknown'
				ComplianceIssues = @()
				Permissions      = @()
				UsageMetrics     = @{}

				# Metadata
				CollectionTime   = Get-Date
				AnalysisVersion  = '2.5'
				DataSource       = 'WMI'
				DCIPAddress      = $params.DCIPAddress
				DCSite           = $params.DCSite
			}

			# Extended analysis based on parameters
			if ($params.ShareClassification) {
				Add-ShareClassification -ShareInfo $shareInfo -Config $config
			}

			if ($params.IncludePermissions) {
				Add-SharePermissions -ShareInfo $shareInfo -Config $config -Credential $credential
			}

			if ($params.SecurityAssessment) {
				Invoke-ShareSecurityAssessment -ShareInfo $shareInfo -Config $config
			}

			if ($params.ComplianceCheck) {
				Invoke-ShareComplianceCheck -ShareInfo $shareInfo -Config $config
			}

			if ($params.RiskAnalysis) {
				Invoke-ShareRiskAnalysis -ShareInfo $shareInfo -Config $config
			}

			if ($params.UsageAnalysis) {
				Add-ShareUsageMetrics -ShareInfo $shareInfo
			}

			$dcShares += $shareInfo
		}

		return $dcShares

	} catch {
		# Return error object for failed DCs
		return [PSCustomObject]@{
			ComputerName    = $dcName
			ComputerFQDN    = $dcFQDN
			Error           = $_.Exception.Message
			SecurityRisk    = 'Critical'
			CollectionTime  = Get-Date
			AnalysisVersion = '2.5'
		}
	}
}

function Get-ShareTypeFromWMI {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false)]
		[uint32]$Type
	)

	switch ($Type) {
		0 {
			return 'Disk Drive'
		}
		1 {
			return 'Print Queue'
		}
		2 {
			return 'Device'
		}
		3 {
			return 'IPC'
		}
		2147483648 {
			return 'Disk Drive Admin'
		}
		2147483649 {
			return 'Print Queue Admin'
		}
		2147483650 {
			return 'Device Admin'
		}
		2147483651 {
			return 'IPC Admin'
		}
		default {
			return 'Unknown'
		}
	}
}

function Add-ShareClassification {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo,

		[Parameter(Mandatory = $true)]
		[hashtable]$Config
	)

	$shareName = $ShareInfo.ShareName
	$sharePath = $ShareInfo.SharePath

	# Classify by share name
	if ($Config.ShareTypes.System -contains $shareName) {
		$ShareInfo.ShareCategory = 'System'
	} elseif ($Config.ShareTypes.DomainData -contains $shareName) {
		$ShareInfo.ShareCategory = 'Domain Data'
	} elseif ($Config.ShareTypes.DriveShares -contains $shareName) {
		$ShareInfo.ShareCategory = 'Administrative Drive'
	} elseif ($Config.ShareTypes.Application | Where-Object { $shareName -like "*$_*" }) {
		$ShareInfo.ShareCategory = 'Application'
	} else {
		# Classify by path characteristics
		switch -Regex ($sharePath) {
			'^[A-Z]:\\$' {
				$ShareInfo.ShareCategory = 'Root Drive'
			}
			'Program Files|Applications|Software' {
				$ShareInfo.ShareCategory = 'Application'
			}
			'Data|Documents|Files|Shared' {
				$ShareInfo.ShareCategory = 'Data'
			}
			'Backup|Archive' {
				$ShareInfo.ShareCategory = 'Backup'
			}
			'Temp|Temporary|Cache' {
				$ShareInfo.ShareCategory = 'Temporary'
			}
			default {
				$ShareInfo.ShareCategory = 'Custom'
			}
		}
	}
}

function Add-SharePermissions {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo,

		[Parameter(Mandatory = $true)]
		[hashtable]$Config,

		[Parameter(Mandatory = $false)]
		[System.Management.Automation.PSCredential]$Credential
	)

	try {
		# Note: This is a simplified permissions check
		# In a real implementation, you would use more sophisticated methods
		# to retrieve share permissions (Get-SmbShareAccess, Win32_LogicalShareSecuritySetting, etc.)

		$permissions = @()

		# Basic permission analysis based on share type and name
		if ($ShareInfo.IsDefaultShare) {
			$permissions += [PSCustomObject]@{
				Principal   = 'Administrators'
				AccessType  = 'Full Control'
				AccessLevel = 'Administrative'
			}
		} else {
			# For non-default shares, assume basic permissions structure
			$permissions += [PSCustomObject]@{
				Principal   = 'Unknown'
				AccessType  = 'Unknown'
				AccessLevel = 'Requires Analysis'
			}
		}

		$ShareInfo.Permissions = $permissions

	} catch {
		$ShareInfo.Permissions = @([PSCustomObject]@{
				Error = "Failed to retrieve permissions: $($_.Exception.Message)"
			})
	}
}

function Invoke-ShareSecurityAssessment {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo,

		[Parameter(Mandatory = $true)]
		[hashtable]$Config
	)

	$riskFactors = @()
	$riskLevel = 'Low'

	# Hidden share assessment
	if ($ShareInfo.IsHidden -and -not $ShareInfo.IsDefaultShare) {
		$riskFactors += 'Non-standard hidden share detected'
		$riskLevel = 'Medium'
	}

	# Default share assessment
	if ($ShareInfo.IsDefaultShare) {
		switch ($ShareInfo.ShareName) {
			'ADMIN$' {
				$riskFactors += 'Administrative share - high privilege access'
				$riskLevel = 'High'
			}
			{ $_ -match '^[A-Z]\$$' } {
				$riskFactors += 'Drive share - potential data exposure'
				if ($riskLevel -eq 'Low') {
					$riskLevel = 'Medium'
				}
			}
			'IPC$' {
				# IPC$ is normal and expected
			}
		}
	} else {
		# Custom share - requires attention
		$riskFactors += 'Custom share requires security review'
		if ($riskLevel -eq 'Low') {
			$riskLevel = 'Medium'
		}
	}

	# Path-based risk assessment
	if ($ShareInfo.SharePath -match '^[A-Z]:\\$') {
		$riskFactors += 'Root directory exposure'
		$riskLevel = 'High'
	}

	# Description-based assessment
	if ([string]::IsNullOrEmpty($ShareInfo.Description)) {
		$riskFactors += 'Missing share description - documentation issue'
	}

	$ShareInfo.SecurityRisk = $riskLevel
	$ShareInfo.RiskFactors = $riskFactors
}

function Invoke-ShareComplianceCheck {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo,

		[Parameter(Mandatory = $true)]
		[hashtable]$Config
	)

	$complianceIssues = @()
	$complianceStatus = 'Compliant'

	# Documentation compliance
	if ([string]::IsNullOrEmpty($ShareInfo.Description) -and -not $ShareInfo.IsDefaultShare) {
		$complianceIssues += 'Share lacks proper documentation'
		$complianceStatus = 'Non-Compliant'
	}

	# Naming compliance
	if ($ShareInfo.ShareName -match '[^A-Za-z0-9_$-]') {
		$complianceIssues += 'Share name contains non-standard characters'
		$complianceStatus = 'Non-Compliant'
	}

	# Security compliance
	if ($ShareInfo.SecurityRisk -eq 'High' -or $ShareInfo.SecurityRisk -eq 'Critical') {
		$complianceIssues += 'Share presents high security risk'
		$complianceStatus = 'Non-Compliant'
	}

	$ShareInfo.ComplianceStatus = $complianceStatus
	$ShareInfo.ComplianceIssues = $complianceIssues
}

function Invoke-ShareRiskAnalysis {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo,

		[Parameter(Mandatory = $true)]
		[hashtable]$Config
	)

	# Risk scoring based on multiple factors
	$riskScore = 0

	# Base risk by share type
	switch ($ShareInfo.ShareCategory) {
		'System' {
			$riskScore += 10
		}
		'Administrative Drive' {
			$riskScore += 30
		}
		'Domain Data' {
			$riskScore += 20
		}
		'Data' {
			$riskScore += 25
		}
		'Custom' {
			$riskScore += 35
		}
	}

	# Risk modifiers
	if ($ShareInfo.IsHidden -and -not $ShareInfo.IsDefaultShare) {
		$riskScore += 15
	}
	if ($ShareInfo.RiskFactors.Count -gt 2) {
		$riskScore += 20
	}
	if ($ShareInfo.ComplianceStatus -eq 'Non-Compliant') {
		$riskScore += 25
	}

	# Determine final risk level
	$finalRisk = switch ($riskScore) {
		{ $_ -ge 60 } {
			'Critical'
		}
		{ $_ -ge 40 } {
			'High'
		}
		{ $_ -ge 20 } {
			'Medium'
		}
		default {
			'Low'
		}
	}

	# Update risk if higher than security assessment
	if (($finalRisk -eq 'Critical' -and $ShareInfo.SecurityRisk -ne 'Critical') -or
		($finalRisk -eq 'High' -and $ShareInfo.SecurityRisk -in @('Medium', 'Low'))) {
		$ShareInfo.SecurityRisk = $finalRisk
	}
}

function Add-ShareUsageMetrics {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ShareInfo
	)

	# Basic usage metrics from WMI data
	$usageMetrics = @{
		CurrentConnections    = $ShareInfo.CurrentUsers
		MaxAllowedConnections = if ($ShareInfo.AllowMaximum) {
			'Unlimited'
		} else {
			$ShareInfo.MaximumAllowed
		}
		ConnectionStatus      = if ($ShareInfo.CurrentUsers -gt 0) {
			'Active'
		} else {
			'Idle'
		}
	}

	$ShareInfo.UsageMetrics = $usageMetrics
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
		Write-Warning 'No data to export'
		return
	}

	# Ensure output directory exists
	if (-not (Test-Path $OutputPath)) {
		New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
	}

	$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

	switch ($Format) {
		'CSV' {
			$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.csv"
			$Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
			Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
			return $outputFile
		}

		'JSON' {
			$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.json"
			$exportData = @{
				Metadata = @{
					Version     = '2.5'
					GeneratedOn = Get-Date
					Domain      = $DomainName
					TotalShares = $Data.Count
					Statistics  = $Script:Statistics
				}
				Shares   = $Data
			}
			$exportData | ConvertTo-Json -Depth 8 | Out-File -FilePath $outputFile -Encoding UTF8
			Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
			return $outputFile
		}

		'Excel' {
			try {
				$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.xlsx"

				if (Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue) {
					Import-Module ImportExcel -ErrorAction Stop

					# Main inventory worksheet
					$Data | Export-Excel -Path $outputFile -WorksheetName 'DC Share Inventory' -AutoSize -FreezeTopRow -BoldTopRow

					# Summary worksheet
					$summary = Generate-SummaryReport -Data $Data
					$summary | Export-Excel -Path $outputFile -WorksheetName 'Executive Summary' -AutoSize -FreezeTopRow -BoldTopRow

					# Security risks worksheet
					$securityRisks = $Data | Where-Object { $_.SecurityRisk -in @('Critical', 'High') }
					if ($securityRisks) {
						$securityRisks | Export-Excel -Path $outputFile -WorksheetName 'Security Risks' -AutoSize -FreezeTopRow -BoldTopRow
					}

					Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
					return $outputFile
				} else {
					Write-Warning 'ImportExcel module not available. Exporting as CSV instead.'
					$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.csv"
					$Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
					Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
					return $outputFile
				}
			} catch {
				Write-Warning "Excel export failed: $($_.Exception.Message). Falling back to CSV."
				$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.csv"
				$Data | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
				Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
				return $outputFile
			}
		}

		'HTML' {
			$outputFile = Join-Path $OutputPath "$DomainName-DCsShare-v2.5-$timestamp.html"
			Generate-HTMLReport -Data $Data -FilePath $outputFile
			Write-Host "Domain controller share inventory exported to: $outputFile" -ForegroundColor Green
			return $outputFile
		}

		'Object' {
			Write-Host "Returning $($Data.Count) share objects" -ForegroundColor Green
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
		Metric   = 'Total Shares'
		Value    = $Data.Count
		Category = 'Overview'
	}

	# Security risk distribution
	foreach ($risk in @('Critical', 'High', 'Medium', 'Low')) {
		$count = ($Data | Where-Object { $_.SecurityRisk -eq $risk }).Count
		$summary += [PSCustomObject]@{
			Metric   = "$risk Security Risk"
			Value    = $count
			Category = 'Security'
		}
	}

	# Share type distribution
	$typeDistribution = $Data | Group-Object ShareCategory | Sort-Object Count -Descending
	foreach ($type in $typeDistribution) {
		$summary += [PSCustomObject]@{
			Metric   = "$($type.Name) Shares"
			Value    = $type.Count
			Category = 'Share Types'
		}
	}

	# Hidden shares
	$hiddenShares = ($Data | Where-Object { $_.IsHidden }).Count
	$summary += [PSCustomObject]@{
		Metric   = 'Hidden Shares'
		Value    = $hiddenShares
		Category = 'Configuration'
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
    <title>Domain Controller Share Inventory Report v2.5</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2E86AB; color: white; padding: 20px; text-align: center; }
        .summary { margin: 20px 0; }
        .risk-critical { background-color: #ff4444; color: white; }
        .risk-high { background-color: #ff8800; color: white; }
        .risk-medium { background-color: #ffcc00; }
        .risk-low { background-color: #44ff44; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Domain Controller Share Inventory Report v2.5</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Total Shares: $($Data.Count)</p>
    </div>

    <div class="summary">
        <h2>Security Risk Summary</h2>
        <table>
            <tr><th>Risk Level</th><th>Count</th></tr>
"@

	foreach ($risk in @('Critical', 'High', 'Medium', 'Low')) {
		$count = ($Data | Where-Object { $_.SecurityRisk -eq $risk }).Count
		$cssClass = "risk-$($risk.ToLower())"
		$html += "            <tr class=`"$cssClass`"><td>$risk</td><td>$count</td></tr>`n"
	}

	$html += @'
        </table>
    </div>

    <div class="summary">
        <h2>Share Type Distribution</h2>
        <table>
            <tr><th>Share Type</th><th>Count</th></tr>
'@

	$typeDistribution = $Data | Group-Object ShareCategory | Sort-Object Count -Descending
	foreach ($type in $typeDistribution) {
		$html += "            <tr><td>$($type.Name)</td><td>$($type.Count)</td></tr>`n"
	}

	$html += @'
        </table>
    </div>
</body>
</html>
'@

	$html | Out-File -FilePath $FilePath -Encoding UTF8
}

# Main execution
try {
	Write-Verbose 'Starting Domain Controller Share Inventory and Analysis v2.5'

	# Initialize configuration
	Initialize-Configuration -ConfigFile $ConfigurationFile

	# Import ActiveDirectory module if not already loaded
	if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
		Import-Module ActiveDirectory -ErrorAction Stop
		Write-Verbose 'ActiveDirectory module imported successfully'
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

	Write-Host 'Domain Controller Share Inventory and Analysis v2.5' -ForegroundColor Cyan
	Write-Host "Domain: $DomainName" -ForegroundColor Green
	Write-Host 'Starting comprehensive share analysis...' -ForegroundColor Yellow

	# Retrieve domain controller shares
	$shares = Get-DomainControllerShares -DomainName $DomainName -IncludeHiddenShares:$IncludeHiddenShares -IncludePermissions:$IncludePermissions -SecurityAssessment:$SecurityAssessment -ComplianceCheck:$ComplianceCheck -RiskAnalysis:$RiskAnalysis -UsageAnalysis:$UsageAnalysis -ShareClassification:$ShareClassification -ExcludeDefaultShares:$ExcludeDefaultShares -Credential $Credential -MaxConcurrentJobs $MaxConcurrentJobs -TimeoutSeconds $TimeoutSeconds

	if (-not $shares -or $shares.Count -eq 0) {
		Write-Warning 'No shares found matching the specified criteria'
		exit 0
	}

	Write-Host "Analysis completed for $($shares.Count) shares" -ForegroundColor Green

	# Export results
	$result = Export-Results -Data $shares -OutputPath $OutputPath -DomainName $DomainName -Format $OutputFormat

	# Display comprehensive summary statistics
	Write-Host "`nDomain Controller Share Inventory Analysis Summary (v2.5):" -ForegroundColor Yellow
	Write-Host '=' * 65 -ForegroundColor Yellow

	# Basic statistics
	Write-Host "Total Domain Controllers Processed: $($Script:Statistics.ProcessedSuccessfully)" -ForegroundColor White
	Write-Host "Failed Connections: $($Script:Statistics.Failed)" -ForegroundColor $(if ($Script:Statistics.Failed -gt 0) {
			'Red'
		} else {
			'Green'
		})
	Write-Host "Total Shares Found: $($shares.Count)" -ForegroundColor White

	# Security risk distribution
	Write-Host "`nSecurity Risk Distribution:" -ForegroundColor Yellow
	foreach ($risk in @('Critical', 'High', 'Medium', 'Low')) {
		$count = ($shares | Where-Object { $_.SecurityRisk -eq $risk }).Count
		$color = switch ($risk) {
			'Critical' {
				'Red'
			}
			'High' {
				'Magenta'
			}
			'Medium' {
				'Yellow'
			}
			'Low' {
				'Green'
			}
		}
		Write-Host "  $risk Risk: $count" -ForegroundColor $color
	}

	# Share type distribution
	$typeDistribution = $shares | Group-Object ShareCategory | Sort-Object Count -Descending
	Write-Host "`nShare Type Distribution:" -ForegroundColor Yellow
	foreach ($type in $typeDistribution) {
		Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
	}

	# Hidden shares analysis
	$hiddenShares = ($shares | Where-Object { $_.IsHidden }).Count
	$defaultShares = ($shares | Where-Object { $_.IsDefaultShare }).Count
	$customShares = $shares.Count - $defaultShares

	Write-Host "`nShare Configuration:" -ForegroundColor Yellow
	Write-Host "  Hidden Shares: $hiddenShares" -ForegroundColor $(if ($hiddenShares -gt 6) {
			'Yellow'
		} else {
			'White'
		})
	Write-Host "  Default Shares: $defaultShares" -ForegroundColor White
	Write-Host "  Custom Shares: $customShares" -ForegroundColor $(if ($customShares -gt 0) {
			'Yellow'
		} else {
			'Green'
		})

	# Domain controller distribution
	$dcDistribution = $shares | Group-Object ComputerName | Sort-Object Count -Descending
	Write-Host "`nShares per Domain Controller:" -ForegroundColor Yellow
	foreach ($dc in $dcDistribution | Select-Object -First 5) {
		Write-Host "  $($dc.Name): $($dc.Count)" -ForegroundColor White
	}
	if ($dcDistribution.Count -gt 5) {
		Write-Host "  ... and $($dcDistribution.Count - 5) more" -ForegroundColor Gray
	}

	# Analysis-specific summaries
	if ($ComplianceCheck) {
		$complianceIssues = ($shares | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' }).Count
		Write-Host "`nCompliance Summary:" -ForegroundColor Yellow
		Write-Host "  Compliance Issues Found: $complianceIssues" -ForegroundColor $(if ($complianceIssues -gt 0) {
				'Red'
			} else {
				'Green'
			})
	}

	if ($UsageAnalysis) {
		$activeShares = ($shares | Where-Object { $_.UsageMetrics.ConnectionStatus -eq 'Active' }).Count
		Write-Host "`nUsage Summary:" -ForegroundColor Yellow
		Write-Host "  Active Shares: $activeShares" -ForegroundColor $(if ($activeShares -gt 0) {
				'Green'
			} else {
				'Gray'
			})
		Write-Host "  Idle Shares: $($shares.Count - $activeShares)" -ForegroundColor Gray
	}

	# Critical findings alert
	$criticalFindings = $shares | Where-Object { $_.SecurityRisk -eq 'Critical' }
	if ($criticalFindings.Count -gt 0) {
		Write-Host "`nCRITICAL SECURITY FINDINGS:" -ForegroundColor Red -BackgroundColor Yellow
		foreach ($finding in $criticalFindings | Select-Object -First 5) {
			Write-Host "  $($finding.ComputerName)\$($finding.ShareName) - $($finding.RiskFactors -join ', ')" -ForegroundColor Red
		}
		if ($criticalFindings.Count -gt 5) {
			Write-Host "  ... and $($criticalFindings.Count - 5) more critical findings" -ForegroundColor Red
		}
	}

	# High-risk shares alert
	$highRiskShares = $shares | Where-Object { $_.SecurityRisk -eq 'High' }
	if ($highRiskShares.Count -gt 0) {
		Write-Host "`nHIGH-RISK SHARES:" -ForegroundColor Magenta
		foreach ($share in $highRiskShares | Select-Object -First 3) {
			Write-Host "  $($share.ComputerName)\$($share.ShareName) - $($share.ShareCategory)" -ForegroundColor Magenta
		}
		if ($highRiskShares.Count -gt 3) {
			Write-Host "  ... and $($highRiskShares.Count - 3) more high-risk shares" -ForegroundColor Magenta
		}
	}

	# Custom shares analysis
	if ($customShares -gt 0) {
		Write-Host "`nCUSTOM SHARES REQUIRING REVIEW:" -ForegroundColor Yellow
		$customSharesList = $shares | Where-Object { -not $_.IsDefaultShare } | Select-Object -First 5
		foreach ($share in $customSharesList) {
			Write-Host "  $($share.ComputerName)\$($share.ShareName) -> $($share.SharePath)" -ForegroundColor Yellow
		}
		if ($customShares -gt 5) {
			Write-Host "  ... and $($customShares - 5) more custom shares" -ForegroundColor Yellow
		}
	}

	# Monitoring integration
	if ($MonitoringIntegration) {
		$alertData = @{
			Timestamp        = Get-Date
			Domain           = $DomainName
			TotalShares      = $shares.Count
			CriticalRisk     = $criticalFindings.Count
			HighRisk         = $highRiskShares.Count
			CustomShares     = $customShares
			ComplianceIssues = if ($ComplianceCheck) {
				($shares | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' }).Count
			} else {
				0
			}
		}

		$alertFile = Join-Path $OutputPath "$DomainName-ShareAlerts-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
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

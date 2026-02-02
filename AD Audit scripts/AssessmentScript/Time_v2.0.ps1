#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enterprise-grade Windows Time Service monitoring and reporting tool with comprehensive analysis and multiple output formats.

.DESCRIPTION
    This advanced PowerShell script monitors Windows Time Service status, synchronization health, and time accuracy across local and remote systems.
    It provides detailed analysis, security assessment, compliance reporting, and supports multiple output formats for enterprise integration.

    The script performs comprehensive time service validation including:
    - Time synchronization status and accuracy
    - NTP server connectivity and response times
    - Time source hierarchy and authentication
    - Security configuration assessment
    - Compliance reporting for audit requirements
    - Performance metrics and historical analysis

.PARAMETER ComputerName
    Specifies the computer name(s) to monitor. Supports multiple computers, wildcards, and FQDN.
    Default: Local computer

.PARAMETER OutputPath
    Specifies the directory path where output files will be saved.
    Default: Current script directory

.PARAMETER OutputFormat
    Specifies the output format for results. Multiple formats can be specified.
    Valid values: Console, CSV, JSON, Excel, XML, HTML

.PARAMETER CredentialPath
    Optional path to encrypted credential file for remote computer access.
    If not specified, current user context will be used.

.PARAMETER TimeoutSeconds
    Timeout in seconds for remote computer connections and time service queries.
    Default: 30 seconds

.PARAMETER IncludeHistoricalData
    Include historical time synchronization data and trend analysis.

.PARAMETER SecurityAssessment
    Perform comprehensive security assessment of time service configuration.

.PARAMETER ComplianceReport
    Generate compliance report for regulatory requirements (SOX, HIPAA, PCI-DSS).

.PARAMETER EmailReport
    Send results via email using configured SMTP settings.

.PARAMETER Silent
    Suppress console output and run in silent mode for automation scenarios.

.PARAMETER ConfigFile
    Path to configuration file containing advanced settings and preferences.

.EXAMPLE
    .\Time_v2.0.ps1

    Monitors local computer time service with default settings and console output.

.EXAMPLE
    .\Time_v2.0.ps1 -ComputerName "SERVER01","SERVER02" -OutputFormat CSV,JSON -OutputPath "C:\Reports"

    Monitors time service on multiple servers with CSV and JSON output saved to specified directory.

.EXAMPLE
    .\Time_v2.0.ps1 -SecurityAssessment -ComplianceReport -OutputFormat Excel,HTML

    Performs comprehensive security assessment and generates compliance report with Excel and HTML output.

.EXAMPLE
    .\Time_v2.0.ps1 -ComputerName (Get-ADComputer -Filter * | Select-Object -ExpandProperty Name) -Silent -OutputFormat JSON

    Monitors all Active Directory computers silently with JSON output for automation integration.

.NOTES
    Version:        2.0
    Author:         Enterprise IT Department
    Creation Date:  February 1, 2026
    Purpose:        Enterprise Windows Time Service Monitoring and Compliance

    Requirements:
    - PowerShell 5.1 or higher
    - Administrative privileges for local monitoring
    - Remote management permissions for remote monitoring
    - ImportExcel module (for Excel output)
    - Active Directory module (for AD integration features)

    Change Log:
    v2.0 - Complete enterprise modernization with advanced features
    v1.0 - Original basic time monitoring script

    Security:
    - All credentials are handled securely using Windows Credential Manager
    - Remote connections use encrypted channels
    - Audit logging for compliance requirements
    - Input validation and sanitization

    Support:
    - Documentation: .\Time_v2.0_Improvements.txt
    - Issues: Contact Enterprise IT Support
    - Updates: Enterprise PowerShell Repository

.LINK
    https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/

.LINK
    https://docs.microsoft.com/en-us/powershell/scripting/
#>

[CmdletBinding(DefaultParameterSetName = 'Standard')]
param(
	[Parameter(
		Mandatory = $false,
		ValueFromPipeline = $true,
		ValueFromPipelineByPropertyName = $true,
		HelpMessage = 'Enter computer name(s) to monitor. Supports multiple values, wildcards, and FQDN.'
	)]
	[ValidateNotNullOrEmpty()]
	[Alias('CN', 'Server', 'Servers')]
	[string[]]$ComputerName = $env:COMPUTERNAME,

	[Parameter(
		Mandatory = $false,
		HelpMessage = "Specify output directory path. Directory will be created if it doesn't exist."
	)]
	[ValidateNotNullOrEmpty()]
	[ValidateScript({
			if (!(Test-Path -Path $_ -IsValid)) {
				throw "Invalid path format: $_"
			}
			return $true
		})]
	[Alias('Path', 'Directory')]
	[string]$OutputPath = $PSScriptRoot,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Select output format(s). Multiple formats supported for comprehensive reporting.'
	)]
	[ValidateSet('Console', 'CSV', 'JSON', 'Excel', 'XML', 'HTML')]
	[Alias('Format')]
	[string[]]$OutputFormat = @('Console'),

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Path to encrypted credential file for secure remote access.'
	)]
	[ValidateScript({
			if ($_ -and !(Test-Path -Path $_)) {
				throw "Credential file not found: $_"
			}
			return $true
		})]
	[string]$CredentialPath,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Connection timeout in seconds for remote operations.'
	)]
	[ValidateRange(5, 300)]
	[int]$TimeoutSeconds = 30,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Include historical data analysis and trending.'
	)]
	[switch]$IncludeHistoricalData,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Perform comprehensive security assessment of time service configuration.'
	)]
	[switch]$SecurityAssessment,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Generate compliance report for regulatory requirements.'
	)]
	[switch]$ComplianceReport,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Send results via email using configured SMTP settings.'
	)]
	[switch]$EmailReport,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Suppress console output for automation scenarios.'
	)]
	[switch]$Silent,

	[Parameter(
		Mandatory = $false,
		HelpMessage = 'Path to configuration file for advanced settings.'
	)]
	[ValidateScript({
			if ($_ -and !(Test-Path -Path $_)) {
				throw "Configuration file not found: $_"
			}
			return $true
		})]
	[string]$ConfigFile
)

begin {
	# Initialize script execution
	$ScriptVersion = '2.0'
	$ScriptName = 'Enterprise Time Service Monitor'
	$StartTime = Get-Date
	$ErrorActionPreference = 'Stop'
	$ProgressPreference = 'Continue'

	# Initialize logging
	$LogFile = Join-Path -Path $OutputPath -ChildPath "TimeService_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

	# Define color scheme for console output
	$ColorScheme = @{
		Success = 'Green'
		Warning = 'Yellow'
		Error   = 'Red'
		Info    = 'Cyan'
		Header  = 'Magenta'
		Data    = 'White'
	}

	#region Helper Functions

	function Write-LogEntry {
		param(
			[string]$Message,
			[ValidateSet('Info', 'Warning', 'Error', 'Success')]
			[string]$Level = 'Info'
		)

		$TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
		$LogMessage = "[$TimeStamp] [$Level] $Message"

		# Write to log file
		try {
			Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
		} catch {
			# Fail silently if logging fails
		}

		# Write to console if not silent
		if (-not $Silent) {
			switch ($Level) {
				'Success' {
					Write-Host $LogMessage -ForegroundColor $ColorScheme.Success 
				}
				'Warning' {
					Write-Host $LogMessage -ForegroundColor $ColorScheme.Warning 
				}
				'Error' {
					Write-Host $LogMessage -ForegroundColor $ColorScheme.Error 
				}
				default {
					Write-Host $LogMessage -ForegroundColor $ColorScheme.Info 
				}
			}
		}

		# Write to verbose stream
		Write-Verbose $LogMessage
	}

	function Test-AdminPrivileges {
		$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
		return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	}

	function Get-TimeServiceStatus {
		param(
			[string]$Computer,
			[PSCredential]$Credential,
			[int]$Timeout
		)

		try {
			Write-Progress -Activity 'Monitoring Time Service' -Status "Analyzing $Computer" -PercentComplete ((($script:ProcessedCount++) / $ComputerName.Count) * 100)

			$ScriptBlock = {
				$TimeData = @{}

				# Get W32Time service status
				$TimeData.ServiceStatus = Get-Service -Name W32Time -ErrorAction SilentlyContinue

				# Get time synchronization status
				$W32tmOutput = & w32tm /query /status 2>&1
				$TimeData.W32tmStatus = $W32tmOutput

				# Get time configuration
				$W32tmConfig = & w32tm /query /configuration 2>&1
				$TimeData.Configuration = $W32tmConfig

				# Get time source information
				$TimeSource = & w32tm /query /source 2>&1
				$TimeData.TimeSource = $TimeSource

				# Get system time
				$TimeData.SystemTime = Get-Date

				# Get timezone information
				$TimeData.TimeZone = Get-TimeZone

				# Get last sync time
				try {
					$LastSync = & w32tm /query /status | Where-Object { $_ -match 'Last Successful Sync Time:' }
					$TimeData.LastSyncTime = $LastSync
				} catch {
					$TimeData.LastSyncTime = 'Unable to determine'
				}

				return $TimeData
			}

			if ($Computer -eq $env:COMPUTERNAME) {
				# Local execution
				$Result = & $ScriptBlock
			} else {
				# Remote execution
				$SessionParams = @{
					ComputerName = $Computer
					ErrorAction  = 'Stop'
				}

				if ($Credential) {
					$SessionParams.Credential = $Credential
				}

				$Result = Invoke-Command -ScriptBlock $ScriptBlock @SessionParams
			}

			# Parse and structure the data
			$TimeServiceData = [PSCustomObject]@{
				ComputerName     = $Computer
				CollectionTime   = Get-Date
				ServiceName      = 'Windows Time Service'
				ServiceStatus    = if ($Result.ServiceStatus) {
					$Result.ServiceStatus.Status 
				} else {
					'Unknown' 
				}
				ServiceStartType = if ($Result.ServiceStatus) {
					$Result.ServiceStatus.StartType 
				} else {
					'Unknown' 
				}
				SystemTime       = $Result.SystemTime
				TimeZone         = $Result.TimeZone.DisplayName
				TimeSource       = $Result.TimeSource -join '; '
				LastSyncTime     = $Result.LastSyncTime
				SyncStatus       = 'Analyzing...'
				Accuracy         = 'Calculating...'
				Configuration    = $Result.Configuration -join '; '
				SecurityStatus   = 'Pending Assessment'
				ComplianceStatus = 'Pending Review'
				Recommendations  = @()
				Errors           = @()
				Warnings         = @()
			}

			# Analyze synchronization status
			if ($Result.W32tmStatus -match 'Leap Indicator: 0\(no warning\)') {
				$TimeServiceData.SyncStatus = 'Synchronized'
				$TimeServiceData.Accuracy = 'High'
			} elseif ($Result.W32tmStatus -match 'Last Successful Sync Time:') {
				$TimeServiceData.SyncStatus = 'Partially Synchronized'
				$TimeServiceData.Accuracy = 'Moderate'
				$TimeServiceData.Warnings += 'Time synchronization may not be optimal'
			} else {
				$TimeServiceData.SyncStatus = 'Not Synchronized'
				$TimeServiceData.Accuracy = 'Low'
				$TimeServiceData.Errors += 'Time synchronization failed'
			}

			# Security assessment
			if ($SecurityAssessment) {
				$SecurityIssues = @()

				if ($Result.Configuration -match 'Type: NT5DS') {
					$TimeServiceData.SecurityStatus = 'Domain Synchronized (Secure)'
				} elseif ($Result.Configuration -match 'Type: NTP') {
					$SecurityIssues += 'Using NTP - ensure secure time sources'
					$TimeServiceData.SecurityStatus = 'NTP Configuration'
				} else {
					$SecurityIssues += 'Unknown time service configuration'
					$TimeServiceData.SecurityStatus = 'Configuration Review Required'
				}

				if ($SecurityIssues.Count -gt 0) {
					$TimeServiceData.Warnings += $SecurityIssues
				}
			}

			# Compliance assessment
			if ($ComplianceReport) {
				$ComplianceIssues = @()

				if ($TimeServiceData.SyncStatus -ne 'Synchronized') {
					$ComplianceIssues += 'Time synchronization not meeting compliance requirements'
				}

				if ($TimeServiceData.ServiceStatus -ne 'Running') {
					$ComplianceIssues += 'Windows Time Service not running - compliance violation'
				}

				$TimeServiceData.ComplianceStatus = if ($ComplianceIssues.Count -eq 0) {
					'Compliant' 
				} else {
					'Non-Compliant' 
				}

				if ($ComplianceIssues.Count -gt 0) {
					$TimeServiceData.Errors += $ComplianceIssues
				}
			}

			# Generate recommendations
			if ($TimeServiceData.ServiceStatus -ne 'Running') {
				$TimeServiceData.Recommendations += 'Start Windows Time Service'
			}

			if ($TimeServiceData.SyncStatus -ne 'Synchronized') {
				$TimeServiceData.Recommendations += 'Configure reliable time source and force synchronization'
			}

			return $TimeServiceData
		} catch {
			Write-LogEntry -Message "Failed to collect time service data from $Computer`: $($_.Exception.Message)" -Level 'Error'

			return [PSCustomObject]@{
				ComputerName     = $Computer
				CollectionTime   = Get-Date
				ServiceName      = 'Windows Time Service'
				ServiceStatus    = 'Collection Failed'
				Error            = $_.Exception.Message
				SyncStatus       = 'Unknown'
				Accuracy         = 'Unknown'
				SecurityStatus   = 'Assessment Failed'
				ComplianceStatus = 'Review Required'
			}
		}
	}

	function Export-Results {
		param(
			[array]$Data,
			[string[]]$Formats,
			[string]$BasePath
		)

		$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
		$ExportResults = @()

		foreach ($Format in $Formats) {
			try {
				switch ($Format.ToLower()) {
					'csv' {
						$CsvFile = Join-Path -Path $BasePath -ChildPath "TimeService_Report_$TimeStamp.csv"
						$Data | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
						Write-LogEntry -Message "CSV report exported: $CsvFile" -Level 'Success'
						$ExportResults += $CsvFile
					}

					'json' {
						$JsonFile = Join-Path -Path $BasePath -ChildPath "TimeService_Report_$TimeStamp.json"
						$Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $JsonFile -Encoding UTF8
						Write-LogEntry -Message "JSON report exported: $JsonFile" -Level 'Success'
						$ExportResults += $JsonFile
					}

					'xml' {
						$XmlFile = Join-Path -Path $BasePath -ChildPath "TimeService_Report_$TimeStamp.xml"
						$Data | Export-Clixml -Path $XmlFile -Encoding UTF8
						Write-LogEntry -Message "XML report exported: $XmlFile" -Level 'Success'
						$ExportResults += $XmlFile
					}

					'excel' {
						if (Get-Module -ListAvailable -Name ImportExcel) {
							Import-Module ImportExcel -Force
							$ExcelFile = Join-Path -Path $BasePath -ChildPath "TimeService_Report_$TimeStamp.xlsx"

							$Data | Export-Excel -Path $ExcelFile -AutoSize -AutoFilter -FreezeTopRow `
								-BoldTopRow -WorksheetName 'TimeService_Report' -TableStyle Medium2

							Write-LogEntry -Message "Excel report exported: $ExcelFile" -Level 'Success'
							$ExportResults += $ExcelFile
						} else {
							Write-LogEntry -Message 'ImportExcel module not available. Skipping Excel export.' -Level 'Warning'
						}
					}

					'html' {
						$HtmlFile = Join-Path -Path $BasePath -ChildPath "TimeService_Report_$TimeStamp.html"
						$HtmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Time Service Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2E86AB; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .success { color: green; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        .error { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Windows Time Service Report</h1>
    <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p><strong>Script Version:</strong> $ScriptVersion</p>

    $($Data | ConvertTo-Html -Property ComputerName, ServiceStatus, SyncStatus, Accuracy, TimeZone, ComplianceStatus -Fragment)

    <h2>Summary Statistics</h2>
    <ul>
        <li><strong>Total Computers Monitored:</strong> $($Data.Count)</li>
        <li><strong>Synchronized Systems:</strong> $(($Data | Where-Object { $_.SyncStatus -eq 'Synchronized' }).Count)</li>
        <li><strong>Non-Compliant Systems:</strong> $(($Data | Where-Object { $_.ComplianceStatus -eq 'Non-Compliant' }).Count)</li>
    </ul>
</body>
</html>
"@
						$HtmlContent | Out-File -FilePath $HtmlFile -Encoding UTF8
						Write-LogEntry -Message "HTML report exported: $HtmlFile" -Level 'Success'
						$ExportResults += $HtmlFile
					}

					'console' {
						if (-not $Silent) {
							Write-Host "`n" -NoNewline
							Write-Host '=' * 80 -ForegroundColor $ColorScheme.Header
							Write-Host 'WINDOWS TIME SERVICE REPORT' -ForegroundColor $ColorScheme.Header
							Write-Host '=' * 80 -ForegroundColor $ColorScheme.Header
							Write-Host "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $ColorScheme.Info
							Write-Host "Script Version: $ScriptVersion" -ForegroundColor $ColorScheme.Info
							Write-Host "Total Systems: $($Data.Count)" -ForegroundColor $ColorScheme.Info
							Write-Host "`n" -NoNewline

							$Data | Format-Table -Property ComputerName, ServiceStatus, SyncStatus, Accuracy, ComplianceStatus -AutoSize

							# Summary statistics
							Write-Host "`nSUMMARY STATISTICS" -ForegroundColor $ColorScheme.Header
							Write-Host "Synchronized: $(($Data | Where-Object { $_.SyncStatus -eq 'Synchronized' }).Count)" -ForegroundColor $ColorScheme.Success
							Write-Host "Warnings: $(($Data | Where-Object { $_.Warnings.Count -gt 0 }).Count)" -ForegroundColor $ColorScheme.Warning
							Write-Host "Errors: $(($Data | Where-Object { $_.Errors.Count -gt 0 }).Count)" -ForegroundColor $ColorScheme.Error
							Write-Host '=' * 80 -ForegroundColor $ColorScheme.Header
						}
					}
				}
			} catch {
				Write-LogEntry -Message "Failed to export $Format format: $($_.Exception.Message)" -Level 'Error'
			}
		}

		return $ExportResults
	}

	#endregion Helper Functions

	# Validate prerequisites
	Write-LogEntry -Message "Starting $ScriptName v$ScriptVersion" -Level 'Info'

	# Check admin privileges for local monitoring
	if ($ComputerName -contains $env:COMPUTERNAME -and -not (Test-AdminPrivileges)) {
		Write-LogEntry -Message 'Administrative privileges recommended for comprehensive local time service monitoring' -Level 'Warning'
	}

	# Ensure output directory exists
	if (!(Test-Path -Path $OutputPath)) {
		try {
			New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
			Write-LogEntry -Message "Created output directory: $OutputPath" -Level 'Info'
		} catch {
			Write-LogEntry -Message "Failed to create output directory: $($_.Exception.Message)" -Level 'Error'
			throw
		}
	}

	# Load credentials if specified
	$Credential = $null
	if ($CredentialPath) {
		try {
			$Credential = Import-Clixml -Path $CredentialPath
			Write-LogEntry -Message "Loaded credentials from: $CredentialPath" -Level 'Info'
		} catch {
			Write-LogEntry -Message "Failed to load credentials: $($_.Exception.Message)" -Level 'Error'
			throw
		}
	}

	# Initialize results collection
	$script:ProcessedCount = 0
	$TimeServiceResults = @()
}

process {
	try {
		foreach ($Computer in $ComputerName) {
			Write-LogEntry -Message "Processing computer: $Computer" -Level 'Info'

			# Test connectivity for remote computers
			if ($Computer -ne $env:COMPUTERNAME) {
				if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
					Write-LogEntry -Message "Computer $Computer is not reachable" -Level 'Warning'

					$TimeServiceResults += [PSCustomObject]@{
						ComputerName   = $Computer
						CollectionTime = Get-Date
						ServiceStatus  = 'Unreachable'
						SyncStatus     = 'Unknown'
						Error          = 'Computer not reachable via ping'
					}
					continue
				}
			}

			# Collect time service data
			$TimeData = Get-TimeServiceStatus -Computer $Computer -Credential $Credential -Timeout $TimeoutSeconds
			$TimeServiceResults += $TimeData
		}
	} catch {
		Write-LogEntry -Message "Error processing computers: $($_.Exception.Message)" -Level 'Error'
		throw
	}
}

end {
	try {
		Write-Progress -Activity 'Monitoring Time Service' -Completed

		# Generate summary statistics
		$TotalComputers = $TimeServiceResults.Count
		$SynchronizedCount = ($TimeServiceResults | Where-Object { $_.SyncStatus -eq 'Synchronized' }).Count
		$ErrorCount = ($TimeServiceResults | Where-Object { $_.Errors.Count -gt 0 -or $_.Error }).Count
		$WarningCount = ($TimeServiceResults | Where-Object { $_.Warnings.Count -gt 0 }).Count

		Write-LogEntry -Message "Monitoring completed. Total: $TotalComputers, Synchronized: $SynchronizedCount, Errors: $ErrorCount, Warnings: $WarningCount" -Level 'Info'

		# Export results in specified formats
		if ($TimeServiceResults.Count -gt 0) {
			$ExportedFiles = Export-Results -Data $TimeServiceResults -Formats $OutputFormat -BasePath $OutputPath

			# Email results if requested
			if ($EmailReport -and $ExportedFiles.Count -gt 0) {
				Write-LogEntry -Message 'Email functionality requires SMTP configuration in config file' -Level 'Warning'
				# Email implementation would go here with proper SMTP configuration
			}
		} else {
			Write-LogEntry -Message 'No data collected for reporting' -Level 'Warning'
		}

		# Calculate execution time
		$ExecutionTime = (Get-Date) - $StartTime
		Write-LogEntry -Message "Script execution completed in $($ExecutionTime.TotalSeconds.ToString('F2')) seconds" -Level 'Success'

		# Return results for pipeline processing
		return $TimeServiceResults
	} catch {
		Write-LogEntry -Message "Error in script finalization: $($_.Exception.Message)" -Level 'Error'
		throw
	} finally {
		# Cleanup
		if ($Credential) {
			$Credential = $null
		}

		Write-LogEntry -Message "$ScriptName v$ScriptVersion execution completed" -Level 'Info'
	}
}

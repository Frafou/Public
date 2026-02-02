
<#
.SYNOPSIS
	Export Domain ACLs

.DESCRIPTION
	Export Domain ACLs

.PARAMETER Switch
    Boolean switch for

.PARAMETER String
    Parameter for

.PARAMETER LogOnly
    Boolean switch for LogOnly

.INPUTS
	.none

.OUTPUTS
	Log:  $ScriptPath\logs\$scriptName.log

.OUTPUTS
	Data:  $ScriptPath\Output\$scriptName.csv

.Example
    Export-DomainACLs.ps1 -verbose
  .Example
    $ScriptName.ps1 -WhatIf

.Notes
    NAME:       Export-DomainACLs.ps1
    AUTHOR:     Francois Fournier
    LAST EDIT:  2025-01-07
		KEYWORDS:   Keyword

    V1.0 Initial version

.link
Https://www.

 #>
<#
#Requires -Version <N>[.<n>]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#Requires -RunAsAdministrator
#>
#Requires -Version 5.1
#Requires -Modules PSLogging

[CmdletBinding()]
param()
#Region Functions
<#
=====================================================
 Function
=====================================================
#>

#EndRegion Functions

#Region Variables
<#
=====================================================
 Variables
=====================================================
#>

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = $logPath + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\output\' + "$CSVName"
$ReportName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.HTML'
$ReportFile = "$ScriptPath" + '\Report\' + "$ReportName"

Write-Verbose "InformationPreference: $InformationPreference"
Write-Verbose "VerbosePreference:$VerbosePreference"
Write-Verbose "LogFile:	$LogFile"
Write-Verbose "DataFile:	$CSVFile"
Write-Verbose "ReportFile:	$ReportFile"

<#
https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.4
Variable	Default Value
$ConfirmPreference = High
$DebugPreference = SilentlyContinue
$ErrorActionPreference = Continue
$InformationPreference = SilentlyContinue
$ProgressPreference = Continue
$VerbosePreference = SilentlyContinue
$WarningPreference = Continue
$WhatIfPreference = $false
$PSModuleAutoLoadingPreference = All
$PSNativeCommandUseErrorActionPreference = $false

$ErrorView = ConciseView
$FormatEnumerationLimit = 4
$LogCommandHealthEvent = $false #(not logged)
$LogCommandLifecycleEvent = $false #(not logged)
$LogEngineHealthEvent = $true #(logged)
$LogEngineLifecycleEvent = $true #(logged)
$LogProviderHealthEvent = $true #(logged)
$LogProviderLifecycleEvent = $true #(logged)
$MaximumHistoryCount = 4096
$OFS #Space character (" ")
$OutputEncoding #UTF8Encoding #object
$PSDefaultParameterValues = @{} #(empty hash table)
$PSEmailServer = $null #(none)
$PSNativeCommandArgumentPassing = Windows #on Windows, Standard on Non-Windows
$PSSessionApplicationName = "wsman"
$PSSessionConfigurationName = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
$PSSessionOption #PSSessionOption object
$PSStyle = $null #PSStyle object
$Transcript = $null #(none)
#>
#EndRegion Variables

#Region Module PSLogging
#--------------------
# Import PSLogging Module
#--------------------

Write-Host 'Importing Logging Module'
if (Get-InstalledModule -Name 'PSLogging') {
	Import-Module PSLogging
} else {
	try {
		Write-Host 'Logging Module not available' -ForegroundColor red

		Write-Host 'Installing Logging Module'
		Install-Module PSLogging
	} catch {
		Write-Error 'Unable to install PSLogging Module'
		exit 1
	}
}
#EndRegion Module PSLogging

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion '1.0' -ToScreen
Write-LogInfo -LogPath $LogFile -Message "Starting script.`n" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tServer: $env:computername" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tScriptPath: $ScriptPath" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tScriptName: $ScriptName" -ToScreen

#Region Modules
#--------------------
# Import Required Modules
#--------------------
Write-LogInfo -LogPath $LogFile -Message 'Importing Required modules' -ToScreen
<#
Write-LogInfo -LogPath $LogFile -Message 'ActiveDirectory' -ToScreen
if (Get-Module -ListAvailable -Name 'ActiveDirectory') {
	Write-Output 'Importing Module ActiveDirectory'
	Import-Module ActiveDirectory
} else {
	Write-Error 'ActiveDirectory Module required'
	Write-Error 'Please install required components (RSAT)'
	exit 1
}
#>
#EndRegion Modules

#Region Process
#--------------------
# Start Processing
#--------------------
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message 'Starting Processing' -ToScreen
#-------------------
# Begin Process
#--------------------

#Region 1
#
$domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName
$ACLs = (Get-Acl -Path "AD:$domaindn").Access
$ACLs | Export-Csv $CSVFile -NoTypeInformation -UseCulture -Encoding utf8

#EndRegion 1

#-----------
#End Processing
#-----------
#EndRegion Process

#Region Finish Script
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message "ReportFile:	$ReportFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "DataFile:		$CSVFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "LogFile:		$LogFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "ReportFile:	$ReportFile" -ToScreen

Stop-Log -LogPath $LogFile -ToScreen -NoExit

#EndRegion Finish Script





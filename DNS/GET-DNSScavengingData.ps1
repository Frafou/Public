<#
.SYNOPSIS
    Retrieves and logs DNS scavenging configuration data from all Domain Controllers in the domain.

.DESCRIPTION
    This script queries all Domain Controllers in the current Active Directory domain to collect
    comprehensive DNS scavenging configuration information. It provides detailed logging of the
    collection process and outputs structured data about scavenging settings including intervals,
    state, and last scavenging time for each Domain Controller.

    The script utilizes the PSLogging module for comprehensive logging and provides execution
    timing information. It's designed for DNS administrators who need to audit and monitor
    scavenging configurations across their DNS infrastructure.

.PARAMETER WhatIf
    When specified, the script will run in WhatIf mode, showing what actions would be performed
    without actually executing them. This parameter is currently implemented as a switch but
    may be reserved for future functionality.

.INPUTS
    None - The script automatically discovers all Domain Controllers in the current domain.

.OUTPUTS
    Console Output: Real-time progress and results displayed to screen
    Log File: Detailed execution log saved to script directory with timestamp
        Format: GET-DNSScavengingData-YYYYMMDD-HHMMSS.log

    Data Collected for Each Domain Controller:
    - Domain Controller Name
    - Scavenging Interval
    - Scavenging State (Enabled/Disabled)
    - Last Scavenging Time
    - Refresh Interval
    - No-Refresh Interval

.EXAMPLE
    .\GET-DNSScavengingData.ps1

    Executes the script and collects DNS scavenging data from all Domain Controllers,
    logging results both to console and timestamped log file.

.EXAMPLE
    .\GET-DNSScavengingData.ps1 -Verbose

    Executes the script with verbose output for additional diagnostic information
    during the data collection process.

.EXAMPLE
    .\GET-DNSScavengingData.ps1 -WhatIf

    Runs the script in WhatIf mode (parameter available for future functionality).

.NOTES
    File Name      : GET-DNSScavengingData.ps1
    Author         : Francois Fournier
    Last Edit      : 2025-11-24
    Version        : 1.5
    Keywords       : DNS, Scavenging, Domain Controllers, Active Directory, Logging

    REQUIREMENTS:
    - PowerShell 5.1 or higher
    - Administrative privileges (RunAsAdministrator)
    - PSLogging PowerShell module
    - Active Directory PowerShell module
    - DNS Server PowerShell module
    - Network connectivity to all Domain Controllers
    - Appropriate permissions to query DNS settings on Domain Controllers

    DEPENDENCIES:
    - PSLogging module (for structured logging)
    - ActiveDirectory module (for Domain Controller discovery)
    - DnsServer module (for DNS scavenging data retrieval)

    FEATURES:
    - Comprehensive logging with PSLogging module
    - Automatic Domain Controller discovery
    - Execution timing and performance metrics
    - Structured console and file output
    - Error handling for unreachable Domain Controllers

    CHANGE LOG:
    2025-11-24 - v1.5 - Francois Fournier - Enhanced logging and documentation

    OUTPUT FILES:
    - Log files are created in the script directory with timestamp
    - Format: GET-DNSScavengingData-YYYYMMDD-HHMMSS.log

.LINK
    https://docs.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverscavenging
    https://docs.microsoft.com/en-us/windows-server/networking/dns/manage-dns-scavenging
    https://github.com/9to5IT/PSLogging

.COMPONENT
    DNS Server Management, Active Directory, System Logging

.ROLE
    DNS Administrator, Domain Administrator, System Administrator

.FUNCTIONALITY
    DNS Infrastructure Monitoring, Scavenging Configuration Audit, System Logging

.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>
#requires -Module PSLogging
#requires -Module ActiveDirectory
#requires -Module DnsServer
#requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = 'Path')]
	[switch]$Whatif
)
#region Variables
<#
	=====================================================
 	Variables
	=====================================================
	#>
#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath"
# Case-insensitive replacement using -replace with (?i)
$Name = $ScriptName -replace '(?i).ps1', ''
$LogName = $Name + '-' + $LogDate + '.log'
$LogFile = $logPath + '\' + "$LogName"
#endregion Variables

#--------------------
# Import Modules
#--------------------

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion '1.5' -ToScreen
Write-LogInfo -LogPath $LogFile -Message 'Starting script.' -ToScreen

#--------------------
# Variables
#--------------------

#--------------------
# Begin Process
#--------------------
#get a list of domain controllers in domain (replace Contoso with your domain)
$DCs = (Get-ADDomainController -Filter *)
#loop through list of DCs and dump lines with "scavenging" in them
foreach ($DC in $DCs) {
	Write-LogInfo -LogPath $LogFile -Message "DC: $DC" -ToScreen

	$output = Get-DnsServerScavenging -ComputerName $DC
	Write-LogInfo -LogPath $LogFile -Message "`tScavenging Interval: $($Output.ScavengingInterval)" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "`tScavenging State: $($Output.ScavengingState)" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "`tLastScavengeTime: $($Output.LastScavengeTime)" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "`tRefresh Interval: $($Output.RefreshInterval)" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "`tNoRefreshInterval: $($Output.NoRefreshInterval)" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "`n" -ToScreen
}
#-----------------END SCRIPT CODE------------------

Write-LogInfo -LogPath $LogFile -Message 'Processing completed' -ToScreen
#-----------
#Finish
#-----------
#The lines below calculates how long
#it takes to run this script
# Get End Time


#send the information to a text file
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen

Write-LogInfo -LogPath $LogFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message "$(($endDTM-$startDTM).TotalSeconds) seconds" -ToScreen

#Append the minutes value to the text file

Write-LogInfo -LogPath $LogFile -Message "$(($endDTM-$startDTM).TotalMinutes) minutes" -ToScreen
Stop-Log -LogPath $LogFile -ToScreen -NoExit

Write-Output "LogPath : $logPath"
Write-Output "LogFile : $LogFile"
#SCRIPT ENDS

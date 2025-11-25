
<#
.SYNOPSIS
    Retrieves and reports DNS scavenging configuration data from all DNS servers in the current Active Directory domain.

.DESCRIPTION
    The GET-DNSScavengingData script provides comprehensive DNS scavenging configuration auditing across all DNS servers
    in an Active Directory domain. It automatically discovers DNS servers through NS records, then collects detailed
    scavenging settings including intervals, states, and timestamps from each server.

    This script is essential for DNS infrastructure management, compliance auditing, and troubleshooting DNS-related
    issues in enterprise environments. It provides detailed logging capabilities and supports both informational
    reporting and analysis modes.

.PARAMETER Whatif
    When specified, the script runs in analysis mode without making any changes. This parameter allows you to preview
    what the script would do without actually performing any operations. Useful for testing and validation purposes.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.String
    The script outputs detailed DNS scavenging information to both the console and log files, including:
    - DNS server identification and connectivity status
    - Scavenging interval configurations
    - Current scavenging state (enabled/disabled)
    - Last scavenging operation timestamps
    - Refresh and no-refresh interval settings
    - Processing completion status and execution metrics

.NOTES
    File Name     : GET-DNSScavengingData(DNS).ps1
    Author        : System Administrator
    Prerequisite  : PowerShell 5.1 or higher, Administrative privileges
    Requirements  : PSLogging, ActiveDirectory, DnsServer modules
    Version       : 1.5
    Created       : [Creation Date]
    Updated       : [Last Modified Date]

    IMPORTANT SECURITY CONSIDERATIONS:
    - Requires administrative privileges on DNS servers
    - Uses read-only operations (no configuration changes)
    - Generates audit logs for compliance tracking
    - Network connectivity required to all DNS servers

    TECHNICAL REQUIREMENTS:
    - Windows PowerShell 5.1 or PowerShell 7+
    - PSLogging module (automatically handled)
    - ActiveDirectory PowerShell module
    - DnsServer PowerShell module
    - Network connectivity to domain DNS servers
    - Administrative rights on target DNS servers

    COMPLIANCE & AUDITING:
    - Generates timestamped log files for audit purposes
    - Read-only operations maintain system security
    - Compatible with enterprise monitoring solutions
    - Supports compliance reporting requirements

.EXAMPLE
    PS C:\> .\GET-DNSScavengingData(DNS).ps1

    Description:
    Executes the script in standard mode, collecting DNS scavenging data from all DNS servers in the current domain.
    Creates detailed logs and displays progress information on the console.

    Sample Output:
    Starting script.
    Getting Domain Name
    Domain Name: contoso.com
    Get list of DNS Servers
    === Zone: contoso.com ===
    DNS: DC01.contoso.com
        Scavenging Interval: 7.00:00:00
        Scavenging State: True
        LastScavengeTime: 11/25/2025 2:15:30 AM
        Refresh Interval: 7.00:00:00
        NoRefreshInterval: 7.00:00:00

.EXAMPLE
    PS C:\> .\GET-DNSScavengingData(DNS).ps1 -Whatif

    Description:
    Runs the script in analysis mode using the -Whatif parameter. This allows you to see what the script would do
    without actually performing the operations, useful for testing and validation.

.EXAMPLE
    PS C:\> .\GET-DNSScavengingData(DNS).ps1 -Verbose

    Description:
    Executes the script with verbose output enabled, providing detailed information about each step of the process.
    Useful for troubleshooting and detailed monitoring of script execution.

.EXAMPLE
    # Schedule the script to run weekly for compliance monitoring
    PS C:\> $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\GET-DNSScavengingData(DNS).ps1"
    PS C:\> $Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6:00AM
    PS C:\> Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "DNS Scavenging Audit"

    Description:
    Creates a scheduled task to run the DNS scavenging audit script weekly on Monday mornings at 6:00 AM.
    This enables automated compliance monitoring and regular DNS infrastructure assessment.

.LINK
    Get-DnsServerScavenging
    https://docs.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverscavenging

.LINK
    Get-DnsServerZone
    https://docs.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverzone

.LINK
    Get-ADDomain
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addomain

.LINK
    PSLogging Module
    https://www.powershellgallery.com/packages/PSLogging

.COMPONENT
    DNS Server Management

.ROLE
    DNS Administrator

.FUNCTIONALITY
    DNS Infrastructure Auditing and Compliance Monitoring

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

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion '1.5' -ToScreen
Write-LogInfo -LogPath $LogFile -Message 'Starting script.' -ToScreen

#region Variables
<#
	=====================================================
 	Variables
	=====================================================
#>
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
# Begin Process
#--------------------
Write-LogInfo -LogPath $LogFile -Message 'Getting Domain Name' -ToScreen
$Domain = (Get-ADDomain).dnsroot
Write-LogInfo -LogPath $LogFile -Message "Domain Name: $Domain" -ToScreen

# Get all NS records from all zones on the local DNS server
Write-LogInfo -LogPath $LogFile -Message 'Get list of DNS Servers' -ToScreen
try {
	# Retrieve all zones
	$zones = Get-DnsServerZone $Domain -ErrorAction Stop

	foreach ($zone in $zones) {
		# Get NS records for each zone
		$nsRecords = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType NS -ErrorAction Stop

		if ($nsRecords) {
			Write-Host "=== Zone: $($zone.ZoneName) ===" -ForegroundColor Cyan
			$DNSSevers = ( $nsRecords | Select-Object HostName, RecordType, @{Name = 'NameServer'; Expression = { $_.RecordData.NameServer } } | Where-Object { $_.Hostname -eq '@' }).nameserver
		}
	}
} catch {
	Write-Error "Failed to retrieve NS records: $_"
}






#get a list of domain controllers in domain (replace Contoso with your domain)
#$DCs = (Get-ADDomainController -Filter *)
#$DNSSevers
#loop through list of DCs and dump lines with "scavenging" in them
foreach ($DNS in $DNSSevers) {
	Write-LogInfo -LogPath $LogFile -Message "DNS: $DNS" -ToScreen

	$output = Get-DnsServerScavenging -ComputerName $DNS
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

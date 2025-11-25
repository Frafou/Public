<#
.SYNOPSIS
    Generates a comprehensive DNS scavenging configuration report for all Domain Controllers.

.DESCRIPTION
    This script queries all Domain Controllers in the current domain to collect DNS scavenging
    configuration details including refresh intervals, no-refresh intervals, scavenging state,
    and last scavenging time. The results are compiled into a detailed report and exported
    to a CSV file for analysis and compliance verification.

    The script helps administrators monitor DNS scavenging settings across their environment
    to ensure proper configuration and identify potential issues with stale DNS records.

.PARAMETER None
    This script does not accept any parameters.

.INPUTS
    None - The script automatically discovers Domain Controllers using Active Directory queries.

.OUTPUTS
    CSV File: DNS_Scavenging_Report.csv
        Contains the following columns:
        - DomainController: FQDN of the Domain Controller
        - RefreshInterval: DNS refresh interval setting
        - NoRefreshInterval: DNS no-refresh interval setting
        - ScavengingState: Current state of DNS scavenging (Enabled/Disabled)
        - LastScavengeTime: Timestamp of the last scavenging operation

    Log File: $ScriptPath\GET-DNSScavengingData.log (if logging is implemented)

.EXAMPLE
    .\PowerShell Script for DNS Scavenging Report.ps1

    Executes the script and generates a DNS scavenging report for all Domain Controllers
    in the current domain, saving results to DNS_Scavenging_Report.csv


.NOTES
    File Name      : PowerShell Script for DNS Scavenging Report.ps1
    Author         : Francois Fournier
    Last Edit      : 2025-11-24
    Version        : 1.0
    Keywords       : DNS, Scavenging, Domain Controllers, Active Directory

    REQUIREMENTS:
    - PowerShell 5.1 or higher
    - Administrative privileges (RunAsAdministrator)
    - Active Directory PowerShell module
    - DNS Server PowerShell module
    - Network connectivity to all Domain Controllers
    - Appropriate permissions to query DNS settings on Domain Controllers

    DEPENDENCIES:
    - ActiveDirectory module
    - DnsServer module

    CHANGE LOG:
    2025-11-24 - v1.0 - Francois Fournier - Initial script creation

.LINK
    https://docs.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverscavenging
    https://docs.microsoft.com/en-us/windows-server/networking/dns/manage-dns-scavenging

.COMPONENT
    DNS Server Management, Active Directory

.ROLE
    DNS Administrator, Domain Administrator, System Administrator

.FUNCTIONALITY
    DNS Scavenging Configuration Reporting and Monitoring

.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>

#requires -Module ActiveDirectory
#requires -Module DnsServer
#requires -Version 5.1
#Requires -RunAsAdministrator
# Import Active Directory module
Import-Module ActiveDirectory

# Get all Domain Controllers in the domain
$DomainControllers = Get-ADDomainController -Filter *

# Initialize an array to store results
$ScavengingReport = @()

# Loop through each Domain Controller
foreach ($DC in $DomainControllers) {
	try {
		# Get DNS scavenging settings for the current Domain Controller
		$ScavengingSettings = Get-DnsServerScavenging -ComputerName $DC.HostName

		# Create a custom object to store the results
		$ReportItem = [PSCustomObject]@{
			DomainController  = $DC.HostName
			RefreshInterval   = $ScavengingSettings.RefreshInterval
			NoRefreshInterval = $ScavengingSettings.NoRefreshInterval
			ScavengingState   = $ScavengingSettings.ScavengingState
			LastScavengeTime  = $ScavengingSettings.LastScavengeTime
		}

		# Add the result to the report array
		$ScavengingReport += $ReportItem
	} catch {
		Write-Warning "Failed to retrieve scavenging settings for $($DC.HostName): $_"
	}
}

# Export the report to a CSV file
$ScavengingReport | Export-Csv -Path '.\DNS_Scavenging_Report.csv' -NoTypeInformation

Write-Host 'DNS scavenging report generated at .\DNS_Scavenging_Report.csv'

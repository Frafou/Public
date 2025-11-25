#requires -module DNSServer
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
			ScavengingState = $ScavengingSettings.ScavengingState
            LastScavengeTime = $ScavengingSettings.LastScavengeTime
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

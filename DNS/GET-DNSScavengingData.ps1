<#
.SYNOPSIS
	List DNS server(s) scavenging information

.DESCRIPTION
	Query all DNS server(s) scavenging information

.INPUTS
	.none

.OUTPUTS
	Log:  $ScriptPath\GET-DNSScavengingData.log

.Example
    GET-DNSScavengingData.ps1 -verbose

.Notes
    NAME:       GET-DNSScavengingData.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2025-11-24
    KEYWORDS:   DNS Scavenging

 #Requires -Version 5.0
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

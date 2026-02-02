<#
.SYNOPSIS
	Export Domain Admins
.DESCRIPTION
	Export Domain Admins

.PARAMETER Whatif
    Will set $WhatifPreference to True
    Refer to powershell documentation for $WhatIfPreference options

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$scriptName.log

.OUTPUTS
	Data:  $scriptPath\$scriptName-$Forest-$Date.csv

.Example
    Export-DomainAdmins.ps1 -verbose

.Example
    Export-DomainAdmins.ps1 -WhatIf

.Notes
    NAME:       Export-DomainAdmins.ps1
    AUTHOR:     Francois Fournier
    LASTEDIT:   2024-11-11
    KEYWORDS:   Keyword

    V1.0 Inital version
    v1.1

.link
Https://www.

 #Requires -Version 5.1
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1)]
	[switch]$Whatif
)

<#
=====================================================
 Variables
=====================================================
#>

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$LogPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = "$ScriptPath" + '\Logs\' + "$LogName"


#$Forests = 'Domain1.local', 'Domain2.local'
$Forests = (Get-ADDomain).DNSRoot

#--------------------
# Import Modules
#--------------------

Write-Host 'Importing Logging Module'
if (Get-InstalledModule -Name 'pslogging') {
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

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion '1.5' -ToScreen
Write-LogInfo -LogPath $LogFile -Message "Starting $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message 'Importing Required modules' -ToScreen

Write-LogInfo -LogPath $LogFile -Message 'ActiveDirectory' -ToScreen
if (Get-Module -ListAvailable -Name 'ActiveDirectory') {
	Write-Output 'Importing Module ActiveDirectory'
	Import-Module ActiveDirectory
} else {
	Write-Error 'ActiveDirectory Module required'
	Write-Error 'Please install required components (RSAT)'
	exit 1
}
#--------------------
# Begin Process
#--------------------
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message 'Starting Processing' -ToScreen
#Set WhatIfPreference
if ($Whatif) {
	$WhatIfPreferencePrevious = $WhatIfPreference
	Write-LogWarning -LogPath $LogFile -Message 'WhatIf Switch applied, setting WhatIf Preference to true' -ToScreen
	$WhatIfPreference = $true
}

foreach ($Forest  in $Forests ) {

	$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $Forest + '-' + $LogDate + '.csv'
	$CSVFile = "$ScriptPath" + '\report\' + "$CSVName"


	Write-LogInfo -LogPath $LogFile -Message "Forest: $Forest" -ToScreen
	$DC = $((Get-ADDomainController -Discover -Domain $forest).hostname)

	$Users = Get-ADGroupMember 'Domain admins' -Server $DC
	$users | Get-ADUser -Server $DC -Properties *  | Select-Object DistinguishedName,	Enabled,	GivenName,	Name,	SamAccountName,	Surname,	UserPrincipalName,  PasswordLastSet, @{name = 'pwdLastSet'; expression = { [datetime]::FromFileTime($_.pwdLastSet).ToString('yyyy-MM-dd_HH:mm:ss') } } | Export-Csv "$CSVFile" -NoTypeInformation










}

#-----------
#Finish
#-----------
if ($Whatif) {
	#reset $WhatifPreference
	Write-Host 'Reverting WhatIf Preference to previous value' -ForegroundColor red
	$WhatIfPreference = $WhatifPreferencePrevious
}
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message "Logfile : $LogFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "CSVfile : $CSVFile" -ToScreen
Stop-Log -LogPath $LogFile -ToScreen -NoExit
#SCRIPT ENDS


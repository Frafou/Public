<#
.SYNOPSIS
	Get AD-User with inheritances disabled

.DESCRIPTION
	Get AD-User with inheritances disabled

.PARAMETER Whatif
    Will set $WhatifPreference to True
    Refer to powershell documentation for $WhatIfPreference options

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$scriptName.log


.Example
  Export-Userswith disabledInheritance.ps1 -verbose

.Example
  Export-Userswith disabledInheritance.ps1 -WhatIf

.Notes
    NAME:       Export-Userswith disabledInheritance.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-08-14
    KEYWORDS:   Inheritance

    V1.0 Initial version
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
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"

#$OU = 'DC=BRP,DC=Local'
$OU = 'OU=BRP Admins,OU=Global,DC=BRP,DC=Local'

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

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion '1.0' -ToScreen
Write-LogInfo -LogPath $logFile -Message "Starting script.`n" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`tserver: $env:computername" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`tScriptPath: $ScriptPath" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`tScriptName: $ScriptName" -ToScreen

Write-LogInfo -LogPath $logFile -Message "`nImporting Required modules" -ToScreen

Write-LogInfo -LogPath $logFile -Message 'ActiveDirectory' -ToScreen
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
Write-LogInfo -LogPath $logFile -Message "`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message 'Starting Processing' -ToScreen

#Set WhatIfPreference
if ($Whatif) {
	$WhatIfPreferencePrevious = $WhatIfPreference
	Write-LogWarning -LogPath $logFile -Message 'WhatIf Switch applied, setting WhatIf Preference to true' -ToScreen
	$WhatIfPreference = $true
}

Write-LogInfo -LogPath $logFile -Message "Loading Users from $OU" -ToScreen

$users = Get-ADUser -SearchBase $OU -Filter * -Properties ntsecuritydescriptor | Where-Object { $_.ntsecuritydescriptor.areaccessrulesprotected -eq $true }

Write-LogInfo -LogPath $logFile -Message "$($Users.count) Users found" -ToScreen
Write-LogInfo -LogPath $logFile -Message 'Processing Users' -ToScreen
Write-LogInfo -LogPath $logFile -Message "`n-------------------" -ToScreen
foreach ($User in $Users) {
	if ( $User.ntsecuritydescriptor.areaccessrulesprotected -eq $true ) {
		Write-LogInfo -LogPath $logFile -Message "SamAccountName: $($user.SamAccountName)" -ToScreen
		Write-LogInfo -LogPath $logFile -Message "Protected: $($User.ntsecuritydescriptor.areaccessrulesprotected)" -ToScreen
	}

}
Write-LogInfo -LogPath $logFile -Message "`n-------------------" -ToScreen
#-----------
#Finish
#-----------
if ($Whatif) {
	#reset $WhatifPreference
	Write-Host 'Reverting WhatIf Preference to previous value' -ForegroundColor red
	$WhatIfPreference = $WhatifPreferencePrevious
}
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS


& $logFile

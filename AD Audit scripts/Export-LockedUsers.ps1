<#
.SYNOPSIS
	Export Locked users and reset VL accounts

.DESCRIPTION
	Export all locked users and reset VL avvounts

.PARAMETER Unlock
    Unlock VL accounts only

.PARAMETER Whatif
    Will set $WhatifPreference to True
    Refer to powershell documentation for $WhatIfPreference options

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$scriptName.log


.Example
  Expport-LockedUsers.ps1 -verbose

.Example
  Expport-LockedUsers.ps1 -WhatIf

.Notes
    NAME:       Export-LockedUsers.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-07-08
    KEYWORDS:   Locked Accounts

    V1.0 Initial version
    v1.1

.link
Https://www.

 #Requires -Version 5.1
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1)]
	[switch]$Unlock,
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


$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.CSV'
$CSVFile = "$ScriptPath" + '\report\' + "$CSVName"

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
Write-LogInfo -LogPath $logFile -Message "Starting $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message 'Importing Required modules' -ToScreen

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
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message 'Starting Processing' -ToScreen
#Set WhatIfPreference
if ($Whatif) {
	$WhatIfPreferencePrevious = $WhatIfPreference
	Write-LogWarning -LogPath $logFile -Message 'WhatIf Switch applied, setting WhatIf Preference to true' -ToScreen
	$WhatIfPreference = $true
}

$Locked = Search-ADAccount -LockedOut
$Locked | Export-Csv $CSVFile -NoTypeInformation -Encoding unicode
Write-LogInfo -LogPath $logFile -Message '------------------------------------' -ToScreen
Write-LogInfo -LogPath $logFile -Message "Processing $($Locked.count) accounts" -ToScreen
Write-LogInfo -LogPath $logFile -Message "------------------------------------`n" -ToScreen

Foreach ($user in $Locked) {
	Write-LogInfo -LogPath $logFile -Message "User: $($user.name)" -ToScreen
	If ((($User.name).Substring(0, 2)) -eq 'VL') {

		if ($unlock) {
			Write-LogInfo -LogPath $logFile -Message "`tUnlocking VL Account" -ToScreen
			try {
				$user | Unlock-ADAccount #-WhatIf
			} catch {

				Write-LogError -LogPath $logFile -Message 'Unable to unlock account' -ToScreen
			}
		}
	}
}


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
Write-LogInfo -LogPath $logFile -Message "CSVfile : $CSVFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS

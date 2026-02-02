<#
.SYNOPSIS
	Export Disabled Users Groups

.DESCRIPTION
	Get's every disabled users groups and exports them to a file

.PARAMETER Param
    Description


.PARAMETER Whatif
    Will set $WhatifPreference to True
    Refer to powershell documentation for $WhatIfPreference options

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$scriptName.log

.OUTPUTS
	Data:  $scriptPath\$scriptName.csv

.Example
    Export-DisabledUsersGroups

.Notes
    NAME:       $ScriptName.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-07-26
    KEYWORDS:   Disabled Users Groups

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
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\' + "$CSVName"


$Forests = 'Brp.local', 'BRPMegatech.local'

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

foreach ($Forest  in $Forests ) {
	Write-LogInfo -LogPath $logFile -Message "`n-------------------------" -ToScreen
	Write-LogInfo -LogPath $logFile -Message "Processing Forest $Forest" -ToScreen
	$DC = $((Get-ADDomainController -Discover -Domain $forest).hostname)
	$CSVFile = "$ScriptPath" + '\' + ($ScriptName).Replace('.ps1', '') + "-$forest-$Date.csv"
	Write-LogInfo -LogPath $logFile -Message 'Getting Disabled Users' -ToScreen
	$Users = Get-ADUser -Filter { (Enabled -eq $False) } -Properties * -Server $DC
	Write-LogInfo -LogPath $logFile -Message "$($users.count) disabled users" -ToScreen
	'Name' + ';' + 'Username' + ';' + 'CanonicalName' + ';' + 'GroupCount' + ';' + 'Groups' | Out-File $CSVFile -Encoding unicode
	foreach ($user in $Users) {
		Write-LogInfo -LogPath $logFile -Message '--------------------' -ToScreen
		Write-LogInfo -LogPath $logFile -Message "User: $($user.name)" -ToScreen
		$Groups = (Get-ADUser $user -Server $DC -Properties memberof).memberof
		$GroupCount = ($groups | Measure-Object).count
		if ($GroupCount -ne 0) {
			Write-LogInfo -LogPath $logFile -Message "User: $($user.name) is member of $GroupCount group(s)" -ToScreen
			$Line = "$($user.name)" + ';' + "$($user.SamAccountName)" + ';' + $($user.CanonicalName ) + ';' + "$GroupCount"

			foreach ($Group in $Groups) {
				Write-LogInfo -LogPath $logFile -Message "$Group" -ToScreen

				$line += (';' + "$Groups" )
			}
			$line | Out-File $CSVFile -Append
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

Write-LogInfo -LogPath $logFile -Message "DataFile : $CSVFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS


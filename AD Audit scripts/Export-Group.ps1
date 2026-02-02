<#
.SYNOPSIS
	Export users from group

.DESCRIPTION
	Get users from group and provide report

.INPUTS
	CSV file with the following header and info
	email, sourcegroup, destinationgroup

.OUTPUTS
	Log:  $scriptPath\Switch-License-yyyyMMdd-hhmmss.log

.Example
     Export-GroupInfo.ps1

.Example
     Export-GroupInfo.ps1 -Megatech

.Notes
    NAME:       Export-GroupInfo.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-07-30
    KEYWORDS:


		V1	initial version

.link
Https://www.

 #Requires -Version 5.0
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
	[switch]$Megatech,
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
	[switch]$Whatif
)

#=====================================================
# Variables
#=====================================================

#Define location of my script variable
#---
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"


#Set WhatIfPrefenrence
$WhatIfPreferencePrevious = $WhatIfPreference
if ($Whatif) {
	$WhatIfPreference = $true
}

#--------------------
# Import Modules
#--------------------

Write-Host 'Importing Logging Module'
if (Get-InstalledModule -Name 'pslogging') {
	Import-Module PSLogging
}
else {
	try {
		Write-Host 'Logging Module not available' -ForegroundColor red

		Write-Host 'Installing Logging Module'
		Install-Module PSLogging
	}
 catch {
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
}
else {
	Write-Error 'ActiveDirectory Module required'
	Write-Error 'Please install required components (RSAT)'
	exit 1
}

#--------------------
# Variables
#--------------------
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message 'Starting Processing' -ToScreen
#--------------------
# Begin Process
#--------------------

Write-LogInfo -LogPath $logFile -Message "`tGetting List of G_BRP_AzureAD_License* group" -ToScreen
$groups = Get-ADGroup -Filter 'Name -like "G_BRP_AzureAD_License*"' | Select-Object name



$groups = Get-ADGroup -Filter 'Name -like "G_BM_AzureAD_License*"' -server caswvdc01.brpmegatech.local | Select-Object name
$Group = ($Groups | Out-GridView -Title "Select Group" -OutputMode single).name
$Members = Get-ADGroup $Group -Properties Member -server caswvdc01.brpmegatech.local  | Select-Object -ExpandProperty Member

Write-LogInfo -LogPath $logFile -Message "`tGetting specific group" -ToScreen
$Group = ($Groups | Out-GridView -Title "Select Group" -OutputMode single).name
$file = "Export-$group-$Date.csv"
Write-LogInfo -LogPath $logFile -Message "`tGetting group membership" -ToScreen
$Members = Get-ADGroup $Group -Properties Member | Select-Object -ExpandProperty Member
Write-LogInfo -LogPath $logFile -Message "`tGetting User Information" -ToScreen
$UserInfo = $Members | Get-ADuser | Select-Object Name, Userprincipalname, enabled
Write-LogInfo -LogPath $logFile -Message "`tExporting Information" -ToScreen
$UserInfo | export-csv $File -NoTypeInformation
Write-LogInfo -LogPath $logFile -Message "`n----------------------------------------" -ToScreen

Write-LogInfo -LogPath $logFile -Message 'Processing completed' -ToScreen
#-----------
#Finish
#-----------

Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit

Write-Output "Logfile : $logFile"
Write-Output "CSVfile : $File"
#reset $WhatifPreference
$WhatIfPreference = $WhatifPreferencePrevious
#SCRIPT ENDS

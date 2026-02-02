<<<<<<< HEAD
<#
.SYNOPSIS
	Export GPO to CSV file

.DESCRIPTION
	Export GPO to CSV file

.OUTPUTS
	Log:  $scriptPath\Export-GPO-yyyy-MM-dd-hh-mm.log

.OUTPUTS
	CSV:  $scriptPath\Export-GPO-yyyy-MM-dd-hh-mm.csv

.Example
    Export-GPO.ps1 -verbose

.Notes
    NAME:       Export-GPO.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-05-21
    KEYWORDS:   GPO

    V1.0 Initial version

.link
https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2022-ps

 #Requires -Version 5.0
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
	[switch]$Whatif
)
#=====================================================
# Variables
#=====================================================

# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$LogPath = $ScriptPath + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\Logs\' + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\Report\' + "$CSVName"

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
Write-LogInfo -LogPath $logFile -Message 'Starting script.' -ToScreen

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
# Variables
#--------------------

#--------------------
# Begin Process
#--------------------

Write-LogInfo -LogPath $logFile -Message 'Starting script.' -ToScreen

$GPOs = Get-GPO -All
foreach ($GPO in $GPOs) {
	mkdir "$ScriptPath\output\$LogDate"
	$GPOName = "$($Gpo.DisplayName).html"
	Get-GPOReport -Name $Gpo.DisplayName -ReportType HTML -Path "$ScriptPath\output\$LogDate\$GPOName"
}

#-----------
#Finish
#-----------
#The lines below calculates how long
#it takes to run this script
# Get End Time
$endDTM = (Get-Date)

# Echo Time elapsed
"Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds"
"Elapsed Time: $(($endDTM-$startDTM).totalminutes) minutes"

#send the information to a text file
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen

Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalseconds) seconds" -ToScreen
Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalminutes) minutes" -ToScreen

Write-LogInfo -LogPath $logFile -Message "LogPath : $logPath" -ToScreen
Write-LogInfo -LogPath $logFile -Message "LogFile : $logFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Datafile : $CSVFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit


#SCRIPT ENDS






=======
<#
.SYNOPSIS
	Export GPO to CSV file

.DESCRIPTION
	Export GPO to CSV file

.OUTPUTS
	Log:  $scriptPath\Export-GPO-yyyy-MM-dd-hh-mm.log

.OUTPUTS
	CSV:  $scriptPath\Export-GPO-yyyy-MM-dd-hh-mm.csv

.Example
    Export-GPO.ps1 -verbose

.Notes
    NAME:       Export-GPO.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-05-21
    KEYWORDS:   GPO

    V1.0 Initial version

.link
https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2022-ps

 #Requires -Version 5.0
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
	[switch]$Whatif
)
#=====================================================
# Variables
#=====================================================

# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$LogPath = $ScriptPath + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\Logs\' + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\Report\' + "$CSVName"

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
Write-LogInfo -LogPath $logFile -Message 'Starting script.' -ToScreen

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
# Variables
#--------------------

#--------------------
# Begin Process
#--------------------

Write-LogInfo -LogPath $logFile -Message 'Starting script.' -ToScreen

$GPOs = Get-GPO -All
foreach ($GPO in $GPOs) {
	mkdir "$ScriptPath\output\$LogDate"
	$GPOName = "$($Gpo.DisplayName).html"
	Get-GPOReport -Name $Gpo.DisplayName -ReportType HTML -Path "$ScriptPath\output\$LogDate\$GPOName"
}

#-----------
#Finish
#-----------
#The lines below calculates how long
#it takes to run this script
# Get End Time
$endDTM = (Get-Date)

# Echo Time elapsed
"Elapsed Time: $(($endDTM-$startDTM).totalseconds) seconds"
"Elapsed Time: $(($endDTM-$startDTM).totalminutes) minutes"

#send the information to a text file
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen

Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalseconds) seconds" -ToScreen
Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalminutes) minutes" -ToScreen

Write-LogInfo -LogPath $logFile -Message "LogPath : $logPath" -ToScreen
Write-LogInfo -LogPath $logFile -Message "LogFile : $logFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Datafile : $CSVFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit


#SCRIPT ENDS






>>>>>>> be44196b159209d1aaeb653fb965a159a27ed321

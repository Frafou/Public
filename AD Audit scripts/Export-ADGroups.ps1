<#
.SYNOPSIS
	Outputs Active Directory Computer information to a CSV file.

.DESCRIPTION
	Quieries Active directory for Group information

.PARAMETER SearchBase
        "The searchbase between quotes or multiple separated with a comma"
.PARAMETER Path
	Specifies a path to csv file. Wildcards are not permitted. The default path is ADGroups-yyyy-MM-dd.csv

.INPUTS
	None


.OUTPUTS
	Log:  $scriptPath\$scriptName.log

.OUTPUTS
	Data:  $scriptPath\$scriptName.csv

.Example
    Export-ADGroups.ps1

.Notes
    NAME:       Export-ADGroups.ps1
    AUTHOR:     Francois Fournier
    LAST EDIT:  2024-12-16

    V1.0 Initial version
    v1.1

.link
Https://www.

 #>
<#
#Requires -Version <N>[.<n>]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#Requires -RunAsAdministrator
#>
#Requires -Version 5.1
#Requires -Modules PSLogging
#Requires -RunAsAdministrator


[CmdletBinding()]
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enter the searchbase between quotes or multiple separated with a comma'
    )]
    [string[]]$searchBase
)

#Region Functions
<#
=====================================================
 Function
=====================================================
#>

#EndRegion Functions
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
$CSVFile = "$ScriptPath" + '\output\' + "$CSVName"

#--------------------
# Import PSLogging Module
#--------------------

Write-Host 'Importing Logging Module'
if (Get-InstalledModule -Name 'PSLogging') {
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
Write-LogInfo -LogPath $logFile -Message "`tServer: $env:computername" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`tScriptPath: $ScriptPath" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`tScriptName: $ScriptName" -ToScreen

#--------------------
# Import Required Modules
#--------------------
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

#-----------------
# Begin Process
#--------------------
Write-LogInfo -LogPath $logFile -Message "`tExporting groups" -ToScreen
$filter = '*'

Write-LogInfo -LogPath $logFile -Message 'Collecting Groups' -ToScreen
# Collect Groups
if ($searchBase) {
    # Get the requested mailboxes
    foreach ($dn in $searchBase) {
        Write-LogInfo -LogPath $logFile -Message "`tGetting groups in $dn" -ToScreen
        $Groups = Get-ADGroup -Filter $filter -SearchBase $dn -Properties Description, DisplayName
    }
} else {
    # Get distinguishedName of the domain
    $dn = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
    Write-LogInfo -LogPath $logFile -Message "`tGetting groups in $dn" -ToScreen
    $Groups = Get-ADGroup -Filter $filter -Properties Description, DisplayName

}
$Groups | Export-Csv -Path $CSVFile -NoTypeInformation -Encoding UTF8 -UseCulture
if ((Get-Item $CSVFile).Length -gt 0) {
    Write-LogInfo -LogPath $logFile -Message "`tGroups exported" -ToScreen
} else {
    Write-LogError -LogPath $logFile -Message "`tFailed to create report" -ToScreen
}

#-----------
#Finish
#-----------

Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "DataFile : $CSVFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "LogFile : $logFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS


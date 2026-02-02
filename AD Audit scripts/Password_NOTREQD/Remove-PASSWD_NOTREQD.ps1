<#
.SYNOPSIS
	Check/remove UserAccount Control setup for PASSWD_NOTREQD

.DESCRIPTION
	Script will  report / remove the PASSWD_NOTREQD option of users

.PARAMETER Export
    Willl export a list of users having the PASSWD_NOTREQD option set

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\Remove-PASSWD-NOTREQD.yyyMMdd-hhmmss.log
    csv:  $scriptPath\Remove-PASSWD-NOTREQD-yyyMMdd-hhmmss.csv

.Example
    Remove-PASSWD-NOTREQDreqd.ps1
.Example
    Remove-PASSWD-NOTREQDreqd.ps1 -Export

.Notes
    NAME:       Remove-PASSWD-NOTREQDreqd.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-02-21

.link
https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

 #Requires -Version 5.0
 #>
[CmdletBinding()]
param(
    [parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
    [switch]$Export,
    [parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
    [switch]$Whatif
)
#=====================================================
# Variables
#=====================================================
#Set WhatIfPrefenrence
$WhatIfPreferencePrevious = $WhatIfPreference
if ($Whatif) {
    $WhatIfPreference = $true
}
# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.CSV'
$CSVFile = "$ScriptPath" + '\output\' + "$CSVName"
$ExcludedUsersList = "$ScriptPath" + '\' + 'ExcludedUsers.txt'
$ExcludedUsersList

#--------------------
# Import Logging Module
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
#--------------------
# Import required Modules
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

#--------------------
# Begin Process
#--------------------
Write-LogInfo -LogPath $logFile -Message "`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message 'Starting Processing' -ToScreen

Write-LogInfo -LogPath $logFile -Message "Checking for excluded users from $ExcludedUsersList" -ToScreen

#Test for User Exclusion File
if (Test-Path $ExcludedUsersList) {
    Write-LogInfo -LogPath $logFile -Message "`tExclusion list found, importing excluded users" -ToScreen
    $ExcludedUsers = Get-Content $ExcludedUsersList -Raw
} else {
    Write-LogInfo -LogPath $logFile -Message "`tExclusion list not found" -ToScreen
    $ExcludedUsers = $null
}

Write-LogInfo -LogPath $logFile -Message 'Getting users with PasswordNotRequired option ' -ToScreen
$users = (Get-ADUser -Filter { PasswordNotRequired -eq $true } -Properties UserAccountControl)
if ($export) {
    Write-LogInfo -LogPath $logFile -Message 'Export option requested' -ToScreen
    Write-LogInfo -LogPath $logFile -Message "Exporting User list file to $CSVFile" -ToScreen
    $users | Export-Csv $CSVFile -NoTypeInformation
} else {
    Write-LogInfo -LogPath $logFile -Message "`nProcessing Users" -ToScreen
    Write-LogInfo -LogPath $logFile -Message "`nProcessing $($Users.count) Users" -ToScreen
    foreach ($User in $Users) {
        Write-LogInfo -LogPath $logFile -Message '--------------' -ToScreen
        Write-LogInfo -LogPath $logFile -Message "Samaccountname: $($User.samaccountname)" -ToScreen
        Write-LogInfo -LogPath $logFile -Message "Name:           $($User.Name)" -ToScreen
        Write-LogInfo -LogPath $logFile -Message "User enabled:   $($User.Enabled)" -ToScreen
        Write-LogInfo -LogPath $logFile -Message "DN:             $($User.DistinguishedName)" -ToScreen

        if ( $ExcludedUsers -contains $($User.samaccountname)) {
            Write-LogInfo -LogPath $logFile -Message "user: $($User.samaccountname) Excluded"
        } else {
            $UACValue = ($user.UserAccountControl)
            Write-LogInfo -LogPath $logFile -Message "`tCurrent UAC Value: $UACValue" -ToScreen
            Write-LogInfo -LogPath $logFile -Message "`tResetting PASSWD_NOTREQD" -ToScreen
            try {
                Set-ADAccountControl $user -PasswordNotRequired $False
            } catch {
                Write-LogError -LogPath $logFile -Message 'Unable to set the option' -ToScreen
                Write-LogError -LogPath $logFile -Message "$error" -ToScreen
            }
        }
    }
}
Write-LogInfo -LogPath $logFile -Message 'Processing completed' -ToScreen
#-----------
#Finish
#-----------
#The lines below calculates how long
#it takes to run this script
# Get End Time
$endDTM = (Get-Date)
#send the information to a text file
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen
Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalseconds) seconds" -ToScreen
Write-LogInfo -LogPath $logFile -Message "$(($endDTM-$startDTM).totalminutes) minutes" -ToScreen

Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Logfile : $CSVFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS
#Resetting WhatIfPreference
$WhatIfPreference = $WhatIfPreferencePrevious

<#
.SYNOPSIS
    Outputs Active Directory Computer information to a CSV file.

.DESCRIPTION
    Quieries Active directory for Computer information including:
            'Name',
            'CanonicalName',
            'OperatingSystem',
            'OperatingSystemVersion',
            'LastLogonDate',
            'LogonCount',
            'BadLogonCount',
            'IPv4Address',
            'Enabled',
            'whenCreated'

.PARAMETER SearchBase
        "The searchbase between quotes or multiple separated with a comma"

.PARAMETER Enabled
       Get computers that are enabled, disabled or both

.PARAMETER Path
    Specifies a path to csv file. Wildcards are not permitted. The default path is ADcomputers-MMM-dd-yyyy.csv

.INPUTS
    None

.OUTPUTS
    CSV:  .\ADcomputers-yyyy-MM-dd.csv"

.Example
    Export-ComputersInfo.ps1

.Notes
    NAME:       Export-ComputersInfo.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2023-07-01
#>

param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enter the searchbase between quotes or multiple separated with a comma'
    )]
    [string[]]$searchBase,
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Get computers that are enabled, disabled or both'
    )]
    [ValidateSet('true', 'false', 'both')]
    [string]$enabled = 'Both',
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enter path to save the CSV file'
    )]
    [string]$CSVFile = ".\ADcomputers-$((Get-Date -Format 'yyyy-MM-dd').ToString()).csv"
)
Function Get-Computers {
    <#
    .SYNOPSIS
      Get computers from the requested DN
    #>
    param(
        [Parameter(
            Mandatory = $true
        )]
        $dn
    )
    process {
        # Set the properties to retrieve
        $properties = @(
            'Name',
            'CanonicalName',
            'OperatingSystem',
            'OperatingSystemVersion',
            'LastLogonDate',
            'LogonCount',
            'lastlogontimestamp',
            'PwdLastSet',
            'PasswordLastSet',
            'BadLogonCount',
            'IPv4Address',
            'Enabled',
            'whenCreated'
        )
        # Get enabled, disabled or both computers
        switch ($enabled) {
            'true' {
                $filter = "enabled -eq 'true'"
            }
            'false' {
                $filter = "enabled -eq 'false'"
            }
            'both' {
                $filter = '*'
            }
        }
        # Get the computers and change timestamp format for Excel
        Get-ADComputer -Filter $filter -SearchBase $dn -Properties $properties | Select-Object Name, CanonicalName, OperatingSystem, OperatingSystemVersion, @{N = 'LastLogonDate'; E = { ($_.LastLogonDate).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'lastlogontimestamp'; E = { [DateTime]::FromFileTime($_.lastlogontimestamp).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'PasswordLastSet'; E = { ($_.PasswordLastSet).ToString('yyyy-MM-dd_HH:mm:ss') } }, LogonCount, BadLogonCount, IPv4Address, Enabled, whenCreated

        #[DateTime]::FromFileTime($_.lastLogonTimestamp).ToString('yyyy-MM-dd_hh:mm:ss')

    }
}
Function Get-AllADComputers {
    <#
    .SYNOPSIS
      Get all AD computers
  #>
    process {
        Write-Host 'Collecting computers' -ForegroundColor Cyan
        Write-LogInfo -LogPath $logFile -Message 'Collecting computers' -ToScreen
        $computers = @()
        # Collect computers
        if ($searchBase) {
            # Get the requested mailboxes
            foreach ($dn in $searchBase) {
                Write-Host "- Get computers in $dn" -ForegroundColor Cyan
                Write-LogInfo -LogPath $logFile -Message "- Get computers in $dn"
                $computers += Get-Computers -dn $dn
            }
        }
        else {
            # Get distinguishedName of the domain
            $dn = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Write-Host "- Get computers in $dn" -ForegroundColor Cyan
            Write-LogInfo -LogPath $logFile -Message "- Get computers in $dn"

            $computers += Get-Computers -dn $dn

        }

        # Loop through all computers
        $computers | ForEach-Object {
            [pscustomobject]@{
                'Name'                 = $_.Name
                'CanonicalName'        = $_.CanonicalName
                'OS'                   = $_.OperatingSystem
                'OS Version'           = $_.OperatingSystemVersion
                'Last Logon'           = $_.lastLogonDate
                'Last Logon timestamp' = $_.lastlogontimestamp
                'PwdLastSet'           = $_.PwdLastSet
                'PasswordLastSet'      = $_.PasswordLastSet
                'Logon Count'          = $_.logonCount
                'Bad Logon Count'      = $_.BadLogonCount
                'IP Address'           = $_.IPv4Address
                'Enabled'              = if ($_.Enabled) {
                    'enabled'
                }
                else {
                    'disabled'
                }
                'Date created'         = $_.whenCreated
            }
        }
    }
}

#=====================================================
# Variables
#=====================================================

# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\Report\' + "$CSVName"

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

#--------------------
# Begin Process
#--------------------

Write-LogInfo -LogPath $logFile -Message "Starting $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message 'Gettng All Computers' -ToScreen
Get-AllADComputers | Sort-Object Name | Export-Csv -Path $CSVFile -NoTypeInformation
if ((Get-Item $CSVFile).Length -gt 0) {
    Write-LogInfo -LogPath $logFile -Message "Report finished and saved in $CSVFile"
    Write-Host "Report finished and saved in $CSVFile" -ForegroundColor Green
    # Open the CSV file
    Invoke-Item $CSVFile
}
else {
    Write-LogError -LogPath $logFile -Message "Report finished and saved in $CSVFile"
    Write-Host 'Failed to create report' -ForegroundColor Red
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
Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Datafile : $CSVFile" -ToScreen

Stop-Log -LogPath $logFile -ToScreen -NoExit
#reset $WhatifPreference
$WhatIfPreference = $WhatifPreferencePrevious
#SCRIPT ENDS

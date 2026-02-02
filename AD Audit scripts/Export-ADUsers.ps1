<#
.SYNOPSIS
	Outputs Active Directory User information to a CSV file.

.DESCRIPTION
	Quieries Active directory for User information
.PARAMETER SearchBase
        "The searchbase between quotes or multiple separated with a comma"
.PARAMETER Path
	Specifies a path to csv file. Wildcards are not permitted. The default path is ADUsers-yyyy-MM-dd.csv


.INPUTS
	None

.OUTPUTS
	CSV:  .\ADUsers-yyyy-MM-dd.csv"

.Example
    Export-ADUsers.ps1 -verbose

.Notes
    NAME:       EXport-ADUsers.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-02-13
#>
#Requires -Version 5.1
#Requires -Modules pslogging
#Requires -RunAsAdministrator
param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enter the searchbase between quotes or multiple separated with a comma'
    )]
    [string[]]$searchBase,
    [Parameter(
        Mandatory = $false,
        HelpMessage = 'Enter path to save the CSV file'
    )]
    [string]$path = ".\ADUsers-$((Get-Date -Format 'yyyy-MM-dd').ToString()).csv"
)

Function Get-AllADUsers {
    <#
    .SYNOPSIS
      Get all AD Users
  #>
    process {
        Write-Host 'Collecting Users' -ForegroundColor Cyan
        # Collect Users
        if ($searchBase) {
            # Get the requested mailboxes
            foreach ($dn in $searchBase) {
                Write-Host "- Get Users in $dn" -ForegroundColor Cyan
                $Users = Get-ADUser -Filter $filter -Properties * -SearchBase $dn | Select-Object AccountExpirationDate, @{Name = 'accountExpiresReadable'; Expression = { [DateTime]::FromFileTime($_.accountExpires) } }, AccountLockoutTime, AccountNotDelegated, AllowReversiblePasswordEncryption, BadLogonCount, @{Name = 'badPasswordTimeReadable'; Expression = { [DateTime]::FromFileTime($_.badPasswordTime) } }, badPwdCount, CannotChangePassword, CanonicalName, City, CN, codePage, Company, Country, countryCode, Created, createTimeStamp, Deleted, Department, Description, DisplayName, DistinguishedName, Division, DoesNotRequirePreAuth, EmailAddress, EmployeeID, EmployeeNumber, Enabled, Fax, GivenName, HomeDirectory, HomedirRequired, HomeDrive, HomePage, HomePhone, Initials, instanceType, isDeleted, LastBadPasswordAttempt, LastKnownParent, lastLogoff, @{N = 'lastLogon'; E = { [DateTime]::FromFileTime($_.lastLogon).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'LastLogonDate'; E = { ($_.LastLogonDate).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'lastlogontimestamp'; E = { [DateTime]::FromFileTime($_.lastlogontimestamp).ToString('yyyy-MM-dd_HH:mm:ss') } }, LockedOut, logonCount, LogonWorkstations, Manager, MemberOf, MNSLogonAccount, MobilePhone, Modified, modifyTimeStamp, Name, Office, OfficePhone, Organization, OtherName, PasswordExpired, PasswordLastSet, @{name = 'pwdLastSet'; expression = { [datetime]::FromFileTime($_.pwdLastSet).ToString('yyyy-MM-dd_HH:mm:ss') } }, PasswordNeverExpires, PasswordNotRequired, PrimaryGroup, primaryGroupID, ProfilePath, ProtectedFromAccidentalDeletion, proxyAddresses, SamAccountName, sAMAccountType, sDRightsEffective, ServicePrincipalNames, sn, Surname, Title, uSNCreated, whenChanged, whenCreated

            }
        } else {
            # Get distinguishedName of the domain
            $dn = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Write-Host "- Get Users in $dn" -ForegroundColor Cyan
            $Users = Get-ADUser -Filter $filter -Properties * | Select-Object AccountExpirationDate, @{Name = 'accountExpiresReadable'; Expression = { [DateTime]::FromFileTime($_.accountExpires) } }, AccountLockoutTime, AccountNotDelegated, AllowReversiblePasswordEncryption, BadLogonCount, @{Name = 'badPasswordTimeReadable'; Expression = { [DateTime]::FromFileTime($_.badPasswordTime) } }, badPwdCount, CannotChangePassword, CanonicalName, City, CN, codePage, Company, Country, countryCode, Created, createTimeStamp, Deleted, Department, Description, DisplayName, DistinguishedName, Division, DoesNotRequirePreAuth, EmailAddress, EmployeeID, EmployeeNumber, Enabled, Fax, GivenName, HomeDirectory, HomedirRequired, HomeDrive, HomePage, HomePhone, Initials, instanceType, isDeleted, LastBadPasswordAttempt, LastKnownParent, lastLogoff, @{N = 'lastLogon'; E = { [DateTime]::FromFileTime($_.lastLogon).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'LastLogonDate'; E = { ($_.LastLogonDate).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'lastlogontimestamp'; E = { [DateTime]::FromFileTime($_.lastlogontimestamp).ToString('yyyy-MM-dd_HH:mm:ss') } }, LockedOut, logonCount, LogonWorkstations, Manager, MemberOf, MNSLogonAccount, MobilePhone, Modified, modifyTimeStamp, Name, Office, OfficePhone, Organization, OtherName, PasswordExpired, PasswordLastSet, @{name = 'pwdLastSet'; expression = { [datetime]::FromFileTime($_.pwdLastSet).ToString('yyyy-MM-dd_HH:mm:ss') } }, PasswordNeverExpires, PasswordNotRequired, PrimaryGroup, primaryGroupID, ProfilePath, ProtectedFromAccidentalDeletion, proxyAddresses, SamAccountName, sAMAccountType, sDRightsEffective, ServicePrincipalNames, sn, Surname, Title, uSNCreated, whenChanged, whenCreated

        }
        return $Users
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
# Variables
#--------------------

#--------------------
# Begin Process
#--------------------

Write-LogInfo -LogPath $logFile -Message "Starting $ScriptName script." -ToScreen


$filter = '*'
Get-AllADUsers | Export-Csv -Path $CSVFile -NoTypeInformation
if ((Get-Item $CSVFile ).Length -gt 0) {
    Write-LogInfo -LogPath $logFile -Message "Report finished and saved in $CSVFile" -ToScreen
    Write-Host "Report finished and saved in $CSVFile" -ForegroundColor Green
    # Open the CSV file
    Invoke-Item $CSVFile
} else {
    Write-LogError -LogPath $logFile -Message "Report finished and saved in $CSVFile" -ToScreen
    Write-Host 'Failed to create report' -ForegroundColor Red
}

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

Write-LogInfo -LogPath $logFile -Message "LogPath : $logPath" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen

Stop-Log -LogPath $logFile -ToScreen -NoExit
#reset $WhatifPreference
$WhatIfPreference = $WhatifPreferencePrevious
#SCRIPT ENDS

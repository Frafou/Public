<#
.SYNOPSIS
	Outputs Active Directory User information to a CSV file.

.DESCRIPTION
	Quieries Active directory for User information


.INPUTS
	UsersToExport.txt

.OUTPUTS
	CSV:  .\ADUsers-yyyy-MM-dd.csv"

.Example
    Export-ADUsers v2.ps1 -verbose

.Notes
    NAME:       Export-ADUsers V2.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-04-23
#>
param()

function Select-FileDialog {
    <#
.SYNOPSIS
	Select-FileDialog.

.DESCRIPTION
	Browse directory tree to select designated file.

.PARAMETER Description
	Specifies a description for the dialog window.

.PARAMETER RootFolder
	Specifies an initial path for the dialo box refer to...

.PARAMETER Filter
	Specifies afilter for file selection.
    https://msdn.microsoft.com/en-us/library/system.windows.forms.filedialog.filter(v=vs.110).aspx

.INPUTS
	None

.OUTPUTS
	None

.Example
    $file = Select-FileDialog -Description "Select a file" -Directory "C:\Temp" -Filter "Powershell Scripts|(*.ps1)"

.Notes
    NAME:     Select-FileDialog
    AUTHOR:   Francois Fournier
    Last Edit:08/24/2017
    KEYWORDS:
.Link
	HTTP://www.

 #Requires -Version 2.0
 #>
    param([string]$Title, [string]$Directory, [string]$Filter = "All Files (*.*)|*.*")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $objForm = New-Object System.Windows.Forms.OpenFileDialog
    $objForm.InitialDirectory = $Directory
    $objForm.Filter = $Filter
    $objForm.Title = $Title
    $Show = $objForm.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = $true }))
    If ($Show -eq "OK") {
        Return $objForm.FileName
    }
    Else {
        Write-Error "Operation cancelled by user."
    }
}
#end function Select-FileDialog
#=====================================================
# Variables
#=====================================================

# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$LogName = ($ScriptName).Replace(".ps1", "") + "-" + $LogDate + ".log"
$logFile = "$ScriptPath" + "\Logs\" + "$LogName"
$CSVName = ($ScriptName).Replace(".ps1", "") + "-" + $LogDate + ".csv"
$CSVFile = "$ScriptPath" + "\" + "$CSVName"

#Set WhatIfPrefenrence
$WhatIfPreferencePrevious = $WhatIfPreference
if ($Whatif) { $WhatIfPreference = $true
}

#--------------------
# Import Modules
#--------------------


Write-Host "Importing Logging Module"
if (Get-InstalledModule -Name "pslogging") {
    Import-module PSLogging
}
else {
    try {
        Write-Host "Logging Module not available" -ForegroundColor red

        Write-Host "Installing Logging Module"
        Install-module PSLogging
    }
    catch {
        Write-Error "Unable to install PSLogging Module"
        exit 1
    }
}

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion "1.5" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Starting script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "Importing Required modules" -ToScreen

Write-LogInfo -LogPath $logFile -Message "ActiveDirectory" -ToScreen
if (Get-Module -ListAvailable -Name "ActiveDirectory") {
    Write-Output "Importing Module ActiveDirectory"
    Import-module ActiveDirectory
}
else {
    Write-Error "ActiveDirectory Module required"
    Write-Error "Please install required components (RSAT)"
    exit 1
}

#--------------------
# Variables
#--------------------

#--------------------
# Begin Process
#--------------------
Write-LogInfo -LogPath $logFile -Message "Starting script." -ToScreen
Write-LogInfo -LogPath $logFile -Message "Selecting Users file" -ToScreen
$PSFile = Select-FileDialog -Description "Select users file" -Directory $ScriptPath -Filter "Text File (*.txt)|*.txt"

$Users = get-content $PSFile
Write-LogInfo -LogPath $logFile -Message "Start processing Users." -ToScreen
$Output = @()
Foreach ($user in $Users) {
    Write-LogInfo -LogPath $logFile -Message "Processing User: $User" -ToScreen
    $Output += Get-ADUser $user -Properties * | Select-Object AccountExpirationDate, @{Name = 'accountExpiresReadable'; Expression = { [DateTime]::FromFileTime($_.accountExpires) } }, AccountLockoutTime, AccountNotDelegated, AllowReversiblePasswordEncryption, BadLogonCount, @{Name = 'badPasswordTimeReadable'; Expression = { [DateTime]::FromFileTime($_.badPasswordTime) } }, badPwdCount, CannotChangePassword, CanonicalName, City, CN, codePage, Company, Country, countryCode, Created, createTimeStamp, Deleted, Department, Description, DisplayName, DistinguishedName, Division, DoesNotRequirePreAuth, EmailAddress, EmployeeID, EmployeeNumber, Enabled, Fax, GivenName, HomeDirectory, HomedirRequired, HomeDrive, HomePage, HomePhone, Initials, instanceType, isDeleted, LastBadPasswordAttempt, LastKnownParent, lastLogoff, @{N = 'lastLogon'; E = { [DateTime]::FromFileTime($_.lastLogon).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'LastLogonDate'; E = { ($_.LastLogonDate).ToString('yyyy-MM-dd_HH:mm:ss') } }, @{N = 'lastlogontimestamp'; E = { [DateTime]::FromFileTime($_.lastlogontimestamp).ToString('yyyy-MM-dd_HH:mm:ss') } }, LockedOut, logonCount, LogonWorkstations, Manager, MemberOf, MNSLogonAccount, MobilePhone, Modified, modifyTimeStamp, Name, Office, OfficePhone, Organization, OtherName, PasswordExpired, PasswordLastSet, @{name = 'pwdLastSet'; expression = { [datetime]::FromFileTime($_.pwdLastSet).ToString('yyyy-MM-dd_HH:mm:ss') } }, PasswordNeverExpires, PasswordNotRequired, PrimaryGroup, primaryGroupID, ProfilePath, ProtectedFromAccidentalDeletion, proxyAddresses, SamAccountName, sAMAccountType, sDRightsEffective, ServicePrincipalNames, sn, Surname, Title, uSNCreated, whenChanged, whenCreated
}

$Output | export-csv $CSVFile -NoTypeInformation
Write-LogInfo -LogPath $logFile -Message "Information written to Data File:  $CSVFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Processing completed." -ToScreen
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

Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen

Stop-Log -LogPath $logFile -ToScreen -NoExit
#reset $WhatifPreference
$WhatIfPreference = $WhatifPreferencePrevious
#SCRIPT ENDS

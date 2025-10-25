<#
.SYNOPSIS
	Create and Install gMSA Account

.DESCRIPTION
	Verify required configuration, create gMSA account in Active Directory and install it on target server.

.PARAMETER gMSAName
    String parameter for gMSA Name

.INPUTS
	.none

.OUTPUTS
	Log:  Install-gMSA_ADAccount-$Date.log


.Example
    Install-gMSA_ADAccount.ps1 -verbose

.Example
    Install-gMSA_ADAccount.ps1 -verbose -MSAName "MSA_ADAssess"


.Notes
    NAME:       Install-gMSA_ADAccount.ps1
    AUTHOR:     Francois Fournier
    LAST EDIT:  2025-10-25

    V1.0 Initial version


.ErrorCodes
	1  Not running as Administrator
	2  Active Directory module installation failed
	3  Active Directory module import failed
	4  Unable to retrieve Forest information from Active Directory.
	5  KDS Root Key creation failed
	6  gMSA account creation failed
	7  gMSA account does not exist in Active Directory
	8  Unable to add gMSA account to 'Enterprise Admins'
	9  Unable to add gMSA account to 'Domain Admins'
	10 gMSA account installation failed
	11 gMSA account validation failed

.link
Https://www.

 #>
<#
#Requires -Version <N>[.<n>]
#Requires -Modules { <Module-Name> | <Hashtable> }
#Requires -PSEdition <PSEdition-Name>
#Requires -Modules PSLogging

#>
#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'MSA account name', Mandatory = $false, Position = 0)]
	[string]$MSAName = 'MSA_ADAssess'
)
begin {
	#Region Variables
	<#
=====================================================
 Global and Literal variables
=====================================================
#>
	$LogDate = Get-Date -Format yyyyMMdd-HHmmss
	$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
	$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
	$logPath = "$ScriptPath"
	$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
	$LogFile = $logPath + '\' + "$LogName"

	$Servername = $env:COMPUTERNAME + '$'
	$MSANameIdentity = $MSAName + '$'
	$OUPath = 'OU=Groups,'
	$Server1 = 'Srv1$'
	$Server2 = 'Srv2$'
	$Server3 = 'Srv3$'

	#endregion Variables

	# Function to write to log
	function Write-Log {
		param (
			[string]$message,
			[string]$level = 'INFO'
		)
		$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
		$logEntry = "$timestamp [$level] $message"
		Add-Content -Path $logFile -Value $logEntry
		Write-Log $logEntry
	}

	function Add-RightToUser([string] $Username, $Right) {
		$tmp = New-TemporaryFile

		$TempConfigFile = "$tmp.inf"
		$TempDbFile = "$tmp.sdb"

		Write-Log 'Getting current policy'
		secedit /export /cfg $TempConfigFile

		$sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value

		$currentConfig = Get-Content -Encoding ascii $TempConfigFile

		$newConfig = $null

		if ($currentConfig | Select-String -Pattern "^$Right = ") {
			if ($currentConfig | Select-String -Pattern "^$Right .*$sid.*$") {
				Write-Log 'Already has right'
			} else {
				Write-Log "Adding $Right to $Username"

				$newConfig = $currentConfig -replace "^$Right .+", "`$0,*$sid"
			}
		} else {
			Write-Log "Right $Right did not exist in config. Adding $Right to $Username."

			$newConfig = $currentConfig -replace '^\[Privilege Rights\]$', "`$0`n$Right = *$sid"
		}

		if ($newConfig) {
			Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig

			Write-Log 'Validating configuration'
			$validationResult = secedit /validate $TempConfigFile

			if ($validationResult | Select-String '.*invalid.*') {
				throw $validationResult;
			} else {
				Write-Log 'Validation Succeeded'
			}

			Write-Log 'Importing new policy on temp database'
			secedit /import /cfg $TempConfigFile /db $TempDbFile

			Write-Log 'Applying new policy to machine'
			secedit /configure /db $TempDbFile /cfg $TempConfigFile

			Write-Log 'Updating policy'
			gpupdate /force

			Remove-Item $tmp* -ea 0
		}
	}



	function Remove-RightFromUser([string] $Username, $Right) {
		$tmp = New-TemporaryFile

		$TempConfigFile = "$tmp.inf"
		$TempDbFile = "$tmp.sdb"

		Write-Log 'Getting current policy'
		secedit /export /cfg $TempConfigFile

		$sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value

		$currentConfig = Get-Content -Encoding ascii $TempConfigFile

		if ($currentConfig | Select-String -Pattern "^$Right .*$sid.*$") {
			Write-Log "Removing $Right from $Username"

			$newConfig = $currentConfig -replace "^($Right = .*?)(?>,\*$sid(.*?$)|\*$sid,(.*?$)|\*$sid$)", '$1$2$3'

			Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig

			Write-Log 'Validating configuration'
			$validationResult = secedit /validate $TempConfigFile

			if ($validationResult | Select-String '.*invalid.*') {
				throw $validationResult;
			} else {
				Write-Log 'Validation Succeeded'
			}

			Write-Log 'Importing new policy on temp database'
			secedit /import /cfg $TempConfigFile /db $TempDbFile

			Write-Log 'Applying new policy to machine'
			secedit /configure /db $TempDbFile /cfg $TempConfigFile

			Write-Log 'Updating policy'
			gpupdate /force

			Remove-Item $tmp* -ea 0
		} else {
			Write-Log "User $Username did not have right"
		}
	}


}

#--------------------
# Start Processing
#--------------------
process {

	Write-Log 'Script started.'

	# Check if running as Administrator
	if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		Write-Log 'Script must be run as Administrator.' 'ERROR'
		exit 1
	}

	# Check OS version
	$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
	Write-Log "Detected OS: $osVersion"

	# Check if Active Directory module is installed
	$featureName = 'RSAT-AD-PowerShell'
	$feature = Get-WindowsFeature -Name $featureName

	if ($feature -and $feature.Installed) {
		Write-Log 'Active Directory PowerShell module is already installed.'
	} else {
		Write-Log 'Active Directory PowerShell module not found. Attempting installation...'
		try {
			Install-WindowsFeature -Name $featureName -IncludeManagementTools -ErrorAction Stop
			Write-Log 'Installation completed successfully.'
		} catch {
			Write-Log "Failed to install the Active Directory module. Error: $_" 'ERROR'
			exit 2
		}
	}

	# Validate module availability
	try {
		Import-Module ActiveDirectory -ErrorAction Stop
		Write-Log 'Active Directory module successfully imported.'
	} catch {
		Write-Log 'Active Directory module could not be imported. Please check the installation.' 'ERROR'
		exit 3
	}
	# Retrieve Forest information
	$Forest = Get-ADDomain
	# Build relative Variables
	$ForestDNSRoot = $Forest.DNSRoot
	$ForestDN = $Forest.DistinguishedName
	$GroupPath = $OUPath + $ForestDN



	if ($null -eq $Forest) {
		Write-Log 'Unable to retrieve Forest information from Active Directory.' -ForegroundColor Red
		exit 4
	} else {
		Write-Log "Forest retrieved: $ForestDNSRoot" -ForegroundColor Green
	}

	if (Get-KdsRootKey) {
		Write-Log 'KDS Root Key already exists. Skipping creation.' -ForegroundColor Green
	} else {
		Write-Log 'Creating KDS Root Key .' -ForegroundColor Green
		try {
			Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
			Start-Sleep -s 10
		} catch {
			Write-Log "Failed to create KDS Root Key: $($_.Exception.Message)" -ForegroundColor Red
			exit 5
		}
	}


	New-ADGroup $MSAName -Path $GroupPath -GroupScope Global -PassThru -Verbose
	Add-ADGroupMember -Identity $MSANameIdentity -Members $Server1, $Server2, $Server3






	try {

		#New-ADServiceAccount -Name $MSAName -DNSHostName "$MSAName.$Forest" -Description "MSA account for ADAssessment on $ServerName" -Enabled $true


		New-ADServiceAccount -Name $MSAName -DNSHostName "$MSAName.$ForestDNSRoot" -PrincipalsAllowedToRetrieveManagedPassword $Servername -Enabled $true -Description "MSA account for ADAssessment on $ServerName"


		#New-ADServiceAccount -Name $MSAName -DNSHostName "$MSAName.$Forest" -PrincipalsAllowedToRetrieveManagedPassword $ServerName -Description "MSA account for ADAssessment on $ServerName" -Enabled $true

		$Identity = Get-ADComputer -Identity $Servername
		Add-ADComputerServiceAccount -Identity $identity -ServiceAccount $MSANameIdentity


	} catch {
		Write-Log "Failed to create gMSA account: $($_.Exception.Message)" -ForegroundColor Red
		exit 6
	}
	## Test gMSA account installation in Server

	if (Get-ADServiceAccount -Identity $MSAName) {
		Write-Log "MSA account $MSAName exists in Active Directory." -ForegroundColor Green
	} else {
		Write-Log "MSA account $MSAName does not exist in Active Directory." -ForegroundColor Red
		exit 7
	}

	Write-Log "Add gMSA account $MSAName to 'Enterprise Admins' group." -ForegroundColor Green
	try {

		Add-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity
		Write-Log 'MSA account added successfully.' -ForegroundColor Green
	} catch {
		Write-Log "Unable to add gMSA account to 'Enterprise Admins': $($_.Exception.Message)" -ForegroundColor Red
		exit 8
	}
	Write-Log "Add gMSA account $MSAName to 'Domain Admins' group." -ForegroundColor Green
	try {
		Add-ADGroupMember -Identity 'Domain Admins' -Members $MSANameIdentity
		Write-Log 'MSA account added successfully.' -ForegroundColor Green
 } catch {
		Write-Log "Unable to add gMSA account to 'Domain Admins': $($_.Exception.Message)" -ForegroundColor Red
		exit 9
	}



	Write-Log 'Adding Logon as a batch Right' -ForegroundColor Green
	try {
		Add-RightToUser -Username $MSANameIdentity -Right 'SeBatchLogonRight'
		Write-Log 'Logon as a batch Right Added' -ForegroundColor Green
	} catch {

		Write-Log "Unable to add gMSA account to 'Domain Admins': $($_.Exception.Message)" -ForegroundColor Red
	}


	#Restart-Computer -Force -Wait -Confirm:$true

	Write-Log "Install gMSA account on $ServerName." -ForegroundColor Green
	try {
		Install-ADServiceAccount -Identity $MSANameIdentity

		Install-ADServiceAccount -Identity $MSAName

		Write-Log "MSA account installed successfully on $ServerName." -ForegroundColor Green
	} catch {
		Write-Log "Failed to install gMSA account: $($_.Exception.Message)" -ForegroundColor Red
		exit 10
	}


	if (Test-ADServiceAccount -Identity $MSANameIdentity) {
		Write-Log "MSA account $MSAName is valid." -ForegroundColor Green
	} else {
		Write-Log "MSA account $MSAName is not valid." -ForegroundColor Red
		exit 11
	}
	#-----------
	# End Processing
	#-----------
	#EndRegion Process
}
end {

	#Region Finish Script


	Write-Log 'Script completed successfully.'
	#EndRegion Finish Script


	break


	Get-ADServiceAccount $MSAName -Properties HostComputers, PrincipalsAllowedToRetrieveManagedPassword | Format-List Name, HostComputers, PrincipalsAllowedToRetrieveManagedPassword


	Uninstall-ADServiceAccount -Identity $MSANameIdentity
	Remove-ADServiceAccount -Identity $MSAName -Confirm:$false
	#Example
	Remove-RightFromUser -Username $MSANameIdentity -Right 'SeBatchLogonRight'
}



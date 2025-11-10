<#
Disclaimer
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. .  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>

<#
.SYNOPSIS
	Create and Install or Remove MSA Account.

.DESCRIPTION
	Verify required configuration, create MSA account in Active Directory and install it on target server, as well as required group membership(s) for Active Directory or Exchange On-Demand Assessment if the corresponding parameter is used.

	if the Remove parameter is used will remove the MSA account and its configuration.

.PARAMETER MSAName
  String parameter for MSA Name.

.PARAMETER Remove
  Switch to remove MSA account.

.PARAMETER AD_ODA
  Switch to add MSA account to required groups for Active Directory On-Demand Assessment.

.PARAMETER EX_ODA
  Switch to add MSA account to required groups for Exchange On-Demand Assessment.

.INPUTS
	.none

.OUTPUTS
	Log:  Install-MSA_ADAccount-$Date.log

.Example
  Install-MSA_ADAccount.ps1 -verbose

.Example
  Install-MSA_ADAccount.ps1 -verbose -MSAName "MSA_ADAssess"

.Notes
  Author: Francois Fournier
  Created: 2025-01-01
  Version: 1.0.0
  Last Updated: 2025-01-01
  License: MIT License
  V1.0 Initial version

.ErrorCodes
	1	MSA length exceeded 15 characters
	2   Script not run as Administrator
	3   Active Directory module installation failed
	4   Active Directory module import failed
	5   Unable to retrieve Forest information
	6   KDS Root Key creation failed
	7   MSA account creation failed
	8   MSA account does not exist in Active Directory
	9   Unable to add MSA account to 'Enterprise Admins'
	10  Unable to add MSA account to 'Domain Admins'
	11  Unable to add MSA account to the Exchange 'Organization Management'
	12  MSA account installation failed
	13  MSA account is not valid
	14	Failed to add 'Log on as a Batch Job' right
	15  Failed to remove 'Log on as a Batch Job' right
	16  Failed to remove ADServiceAccount
	17  Failed to remove MSA account
	18  Unable to remove MSA account to 'Enterprise Admins'
	19  Unable to remove MSA account to 'Domain Admins'
	20  Unable to remove MSA account to the Exchange 'Organization Management'

.LINK
 	https://woshub.com/group-managed-service-accounts-in-windows-server-2012/
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
	[string]$MSAName = 'MSA_ADAssess',

	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Remove MSA account', Mandatory = $false, Position = 1)]
	[switch]$Remove,

	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Remove MSA account', Mandatory = $false, Position = 1)]
	[switch]$AD_ODA,

	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Remove MSA account', Mandatory = $false, Position = 1)]
	[switch]$EX_ODA

)
# =============================================================================
#region begin
begin {
	##region Variables
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

	#endregion Variables
	#region Functions
	# Function to write to log
	function Write-Log {
		param (
			[Parameter(Mandatory = $true)]
			[string]$Message,

			[Parameter(Mandatory = $true)]
			[ValidateSet('INFO', 'WARNING', 'ERROR', 'DEBUG')]
			[string]$Level
		)
		$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
		$logEntry = "$timestamp [$level] $message"
		Add-Content -Path $logFile -Value $logEntry
		switch ($Level) {
			'INFO' {
				Write-Host "[INFO] $Message" -ForegroundColor Green
			}
			'WARNING' {
				Write-Host "[WARNING] $Message" -ForegroundColor Yellow
			}
			'ERROR' {
				Write-Host "[ERROR] $Message" -ForegroundColor Red
			}
			'DEBUG' {
				Write-Host "[DEBUG] $Message" -ForegroundColor Cyan
			}
		}
	}


	function Add-RightToUser([string] $Username, $Right) {
		<# Add error handling#>
		$tmp = New-TemporaryFile

		$TempConfigFile = "$tmp.inf"
		$TempDbFile = "$tmp.sdb"

		Write-Log 'Getting current policy' -Level 'INFO'
		secedit /export /cfg $TempConfigFile

		$sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value

		$currentConfig = Get-Content -Encoding ascii $TempConfigFile

		$newConfig = $null

		if ($currentConfig | Select-String -Pattern "^$Right = ") {
			if ($currentConfig | Select-String -Pattern "^$Right .*$sid.*$") {
				Write-Log 'Already has right' -Level 'INFO'
			} else {
				Write-Log "Adding $Right to $Username" -Level 'INFO'

				$newConfig = $currentConfig -replace "^$Right .+", "`$0,*$sid"
			}
		} else {
			Write-Log "Right $Right did not exist in config. Adding $Right to $Username." -Level 'INFO'

			$newConfig = $currentConfig -replace '^\[Privilege Rights\]$', "`$0`n$Right = *$sid"
		}

		if ($newConfig) {
			Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig

			Write-Log 'Validating configuration' -Level 'INFO'
			$validationResult = secedit /validate $TempConfigFile

			if ($validationResult | Select-String '.*invalid.*') {
				throw $validationResult;
			} else {
				Write-Log 'Validation Succeeded' -Level 'INFO'
			}

			Write-Log 'Importing new policy on temp database' -Level 'INFO'
			secedit /import /cfg $TempConfigFile /db $TempDbFile

			Write-Log 'Applying new policy to machine' -Level 'INFO'
			secedit /configure /db $TempDbFile /cfg $TempConfigFile

			Write-Log 'Updating policy' -Level 'INFO'
			gpupdate /force

			Remove-Item $tmp* -ea 0
		}
	}

	function Remove-RightFromUser([string] $Username, $Right) {
		<# Add error handling#>
		$tmp = New-TemporaryFile

		$TempConfigFile = "$tmp.inf"
		$TempDbFile = "$tmp.sdb"

		Write-Log 'Getting current policy' -Level 'INFO'
		secedit /export /cfg $TempConfigFile

		$sid = ((New-Object System.Security.Principal.NTAccount($Username)).Translate([System.Security.Principal.SecurityIdentifier])).Value

		$currentConfig = Get-Content -Encoding ascii $TempConfigFile

		if ($currentConfig | Select-String -Pattern "^$Right .*$sid.*$") {
			Write-Log "Removing $Right from $Username" -Level 'INFO'

			$newConfig = $currentConfig -replace "^($Right = .*?)(?>,\*$sid(.*?$)|\*$sid,(.*?$)|\*$sid$)", '$1$2$3'

			Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig

			Write-Log 'Validating configuration' -Level 'INFO'
			$validationResult = secedit /validate $TempConfigFile

			if ($validationResult | Select-String '.*invalid.*') {
				throw $validationResult;
			} else {
				Write-Log 'Validation Succeeded' -Level 'INFO'
			}

			Write-Log 'Importing new policy on temp database' -Level
			secedit /import /cfg $TempConfigFile /db $TempDbFile

			Write-Log 'Applying new policy to machine' -Level 'INFO'
			secedit /configure /db $TempDbFile /cfg $TempConfigFile

			Write-Log 'Updating policy' -Level 'INFO'
			gpupdate /force

			Remove-Item $tmp* -ea 0
		} else {
			Write-Log "User $Username did not have right" -Level 'INFO'
		}
	}
	#endregion Functions
}
#endregion begin
# =============================================================================
#region Process
#--------------------
# Start Processing
#--------------------
process {

	Write-Log 'Script started.' -Level 'INFO'


	if ($MSAName.Length -ge 15) {
		Write-Log 'MSA Name must be less than 15 characters.' -Level 'ERROR'
		exit 1
	} else {
		Write-Log 'MSA Name is valid.' -Level 'INFO'
	}

	# Check if running as Administrator
	if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
		Write-Log 'Script must be run as Administrator.' -Level 'ERROR'
		exit 2
	}

	# Check OS version
	$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
	Write-Log "Detected OS: $osVersion" -Level 'INFO'

	# Check if Active Directory module is installed
	$featureName = 'RSAT-AD-PowerShell'
	$feature = Get-WindowsFeature -Name $featureName

	if ($feature -and $feature.Installed) {
		Write-Log 'Active Directory PowerShell module is already installed.' -Level 'WARNING'
	} else {
		Write-Log 'Active Directory PowerShell module not found. Attempting installation...' -Level 'ERROR'
		try {
			Install-WindowsFeature -Name $featureName -IncludeManagementTools -ErrorAction Stop
			Write-Log 'Installation completed successfully.' -Level 'INFO'
		} catch {
			Write-Log "Failed to install the Active Directory module. Error: $_" -Level 'ERROR'
			exit 3
		}
	}

	# Validate module availability
	try {
		Import-Module ActiveDirectory -ErrorAction Stop
		Write-Log 'Active Directory module successfully imported.' -Level 'INFO'
	} catch {
		Write-Log 'Active Directory module could not be imported. Please check the installation.' -Level 'ERROR'
		exit 4
	}

	$Forest = (Get-ADDomain).Forest
	if ($null -eq $Forest) {
		Write-Log 'Unable to retrieve Forest information from Active Directory.' -Level 'ERROR'
		exit 5
	} else {
		Write-Log "Forest retrieved: $Forest" -Level 'INFO'
	}


	if ($Remove) {

		# Remove from groups if required
		if ($AD_ODA) {
			Write-Log "Removing MSA account $MSAName to 'Enterprise Admins' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 9
			}

			Write-Log "Removing MSA account $MSAName to 'Domain Admins' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 9
			}
		}
		if ( $EX_ODA) {
			Write-Log "Removing MSA account $MSAName to 'Organization Management' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity ''Organization Management'' -Members $MSANameIdentity
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 9
			}
		}

		# Remove MSA account
		Write-Log 'Removing MSA configuration.' -Level 'INFO'

		Write-Log "Removing 'Log on as a Batch Job' right." -Level 'INFO'
		try {
			Remove-RightFromUser -Username $MSANameIdentity -Right 'SeBatchLogonRight'
			Write-Log "'Log on as a Batch Job' right removed successfully." -Level 'INFO'
		} catch {
			Write-Log "Failed to remove 'Log on as a Batch Job' right : $($_.Exception.Message)" -Level 'ERROR'
			exit 15
		}

		Write-Log "Uninstall ADServiceAccount $MSANameIdentity." -Level 'INFO'
		try {
			Uninstall-ADServiceAccount -Identity $MSANameIdentity
			Write-Log 'ADServiceAccount removed successfully.' -Level 'INFO'
		} catch {
			Write-Log "Failed to remove ADServiceAccount: $($_.Exception.Message)" -Level 'ERROR'
			exit 16
		}

		Write-Log "Removing MSA account $MSAName." -Level 'INFO'
		try {
			Remove-ADServiceAccount -Identity $MSAName -Confirm:$false
			Write-Log "MSA account $MSAName removed successfully." -Level 'INFO'
		} catch {
			Write-Log "Failed to remove MSA account: $($_.Exception.Message)" -Level 'ERROR'
			exit 17
		}


	} else {

		if (Get-KdsRootKey) {
			Write-Log 'KDS Root Key already exists. Skipping creation.' -Level 'INFO'
		} else {
			Write-Log 'Creating KDS Root Key .' -Level 'INFO'
			try {
				Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
				Start-Sleep -s 10
			} catch {
				Write-Log "Failed to create KDS Root Key: $($_.Exception.Message)" -Level 'ERROR'
				exit 6
			}
		}

		Write-Log 'ADServiceAccount -Name $MSAName.' -Level 'INFO'
		try {

			New-ADServiceAccount -Name $MSAName -RestrictToSingleComputer -Enabled $true -Description "MSA account for ADAssessment on $ServerName"
			Write-Log "MSA account $MSAName created successfully." -Level 'INFO'

			$Identity = Get-ADComputer -Identity $Servername
			Add-ADComputerServiceAccount -Identity $identity -ServiceAccount $MSANameIdentity
			Write-Log "Adding Host $Servername to MSA account $MSAName." -Level 'INFO'


		} catch {
			Write-Log "Failed to create MSA account: $($_.Exception.Message)" -Level 'ERROR'
			exit 7
		}
		## Test MSA account installation in Server

		if (Get-ADServiceAccount -Identity $MSAName) {
			Write-Log "MSA account $MSAName exists in Active Directory." -Level 'INFO'
		} else {
			Write-Log "MSA account $MSAName does not exist in Active Directory." -Level 'ERROR'
			exit 8
		}
		<#
		Active Directory On-Demand Assessment
		#>
		if ($AD_ODA) {
			Write-Log "Add MSA account $MSAName to 'Enterprise Admins' group." -Level 'INFO'
			try {

				Add-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity
				Write-Log 'MSA account added successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 9
			}
			Write-Log "Add MSA account $MSAName to 'Domain Admins' group." -Level 'INFO'
			try {
				Add-ADGroupMember -Identity 'Domain Admins' -Members $MSANameIdentity
				Write-Log 'MSA account added successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Domain Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 10
			}
		}
		<#
		Exchange On-Demand Assessment
		#>
		if ($EX_ODA) {
			Write-Log "Add MSA account $MSAName to 'Exchange Admins' group." -Level 'INFO'
			try {

				Add-ADGroupMember -Identity 'Organization Management' -Members $MSANameIdentity
				Write-Log 'MSA account added successfully.' -Level 'INFO'
			} catch {
				Write-Log "Unable to add MSA account to 'Exchange Organization Management': $($_.Exception.Message)" -Level 'ERROR'
				exit 11
			}

		}
		<#
		Logon as a batch job Right
		#>

		Write-Log 'Adding Logon as a batch job Right' -Level 'INFO'
		try {
			Add-RightToUser -Username $MSANameIdentity -Right 'SeBatchLogonRight'
			Write-Log 'Logon as a batch Job Right Added' -Level 'INFO'
		} catch {

			Write-Log "Unable to add Logon as a batch Job right: $($_.Exception.Message)" -Level 'ERROR'
			exit 14
		}

		Write-Log "Install MSA account on $ServerName." -Level 'INFO'
		try {
			Install-ADServiceAccount -Identity $MSANameIdentity
			Write-Log "MSA account installed successfully on $ServerName." -Level 'INFO'
		} catch {
			Write-Log "Failed to install MSA account: $($_.Exception.Message)" -Level 'ERROR'
			exit 12
		}


		if (Test-ADServiceAccount -Identity $MSANameIdentity) {
			Write-Log "MSA account $MSAName is valid." -Level 'INFO'
		} else {
			Write-Log "MSA account $MSAName is not valid." -Level 'ERROR'
			exit 13
		}

		#-----------
		# End Processing
		#-----------

	}
}
#endregion Process
# =============================================================================
#region End
end {


	Write-Log 'Script completed successfully.' -Level 'INFO'

}
#endregion End

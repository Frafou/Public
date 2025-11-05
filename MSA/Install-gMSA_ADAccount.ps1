<#
Disclaimer
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. .  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
#>

<#
.SYNOPSIS
	Create and Install gMSA Account

.DESCRIPTION
	Verify required configuration, create gMSA account in Active Directory and install it on target server.

.PARAMETER gMSAName
  String parameter for gMSA Name

.PARAMETER gMSAFQDN
  String parameter for gMSA Fully Qualified Domain Name

.PARAMETER gMSAGroupName
    String parameter for gMSA GroupName

.PARAMETER gMSAGroupServer
    Array of String parameter for gMSA Group Servers

.PARAMETER Remove
    Switch to remove gMSA account.

.INPUTS
	.none

.OUTPUTS
	Log:  Install-gMSA_ADAccount-$Date.log

.Example
    Install-gMSA_ADAccount.ps1 -verbose

.Example
    Install-gMSA_ADAccount.ps1 -verbose -MSAName "MSA_ADAssess"

.Notes
    Author: Francois Fournier
    Created: 2025-01-01
    Version: 1.0.0
    Last Updated: 2025-01-01
    License: MIT License

    V1.0 Initial version

.DISCLAIMER
  This script is provided "as is" without warranty of any kind, either express or implied.
  Use of this script is at your own risk. The author assumes no responsibility for any
  damage or loss resulting from the use or misuse of this script.

  You are free to modify and distribute this script, provided that this disclaimer remains
  intact and visible in all copies and derivatives.

  Always test scripts in a safe environment before deploying to production.


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
	[string]$gMSAName = 'MSA_ADAssess',
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'MSA account name', Mandatory = $false, Position = 0)]
	[string]$gMSAFQDN = 'MSA_ADAssess',
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'MSA account name', Mandatory = $false, Position = 0)]
	[string]$gMSAGroupName = 'MSA_ADAssessGroup',
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'MSA account name', Mandatory = $false, Position = 0)]
	[string[]]$gMSAGroupServers = @('Srv1$', 'Srv2$', 'Srv3$'),
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Remove MSA account', Mandatory = $false, Position = 1)]
	[switch]$Remove

)

# =============================================================================
#region begin
begin {
	# =============================================================================
	#region Variables
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

	$MSANameIdentity = $MSAName + '$'
	$OUPath = 'OU=Groups,'

	#endregion Variables

	# =============================================================================
	#region Functions

	function Write-Log {
		# Function to write to log file and console
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

	# Example Usage
	Write-Log -Message 'This is an informational message.' -Level 'INFO'
	Write-Log -Message 'This is a warning message.' -Level 'WARNING'
	Write-Log -Message 'This is an error message.' -Level 'ERROR'
	Write-Log -Message 'This is a debug message.' -Level 'DEBUG'

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

	#endregion Functions

}
#endregion begin
# =============================================================================
#region process
#--------------------
# Start Processing
#--------------------
process {

	Write-Log 'Script started.'


	Write-Log 'Script on not been vetted. Use at your own risk.' 'WARNING' -Level 'Warning'
	break

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
		Write-Log 'Unable to retrieve Forest information from Active Directory.' -Level 'Error'
		exit 4
	} else {
		Write-Log "Forest retrieved: $ForestDNSRoot" -Level 'INFO'
	}

	if (Get-KdsRootKey) {
		Write-Log 'KDS Root Key already exists. Skipping creation.' -Level 'INFO'
	} else {
		Write-Log 'Creating KDS Root Key .' -Level 'INFO'
		try {
			Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))
			Start-Sleep -s 10
		} catch {
			Write-Log "Failed to create KDS Root Key: $($_.Exception.Message)" -Level 'Error'
			exit 5
		}
	}


	if ($Remove) {

		# Remove MSA account
		Write-Log 'Removing MSA configuration.' -Level 'INFO'


		# Install gMSA account on target server
		foreach ($ServerName in $gMSAGroupServers) {
			Write-Log "Install gMSA account on $ServerName." -Level 'INFO'

			$Return = Invoke-Command -ComputerName $ServerName -ScriptBlock {
				param ($MSANameIdentity, $ServerName)

				try {
					Install-ADServiceAccount -Identity $MSANameIdentity

					exit 0
				} catch {

					exit 1
				}
			}
			if ($Return -eq 1) {
				Write-Log "gMSA account installation failed on $ServerName." -Level 'Error'
			} else {
				Write-Log "gMSA account installed successfully on $ServerName." -Level 'INFO'
			}


			$Return = Invoke-Command -ComputerName $ServerName -ScriptBlock {
				if (Test-ADServiceAccount -Identity $MSANameIdentity) {
					exit 0
				} else {

					exit 1
				}
			}
			if ($Return -eq 1) {
				Write-Log "gMSA account validation failed on $ServerName." -Level 'Error'
				exit 11
			} else {
				Write-Log "gMSA account validated successfully on $ServerName." -Level 'INFO'



				try {
					Add-ADGroupMember -Identity $MSANameIdentity -Members $ServerName
				} catch {
					Write-Log "Failed to add servers to group $ServerName : $($_.Exception.Message)" -Level 'Error'
				}


			}
		}




	} else {

		# Create gMSA account
		Write-Log "Creating gMSA account $MSAName in Active Directory." -Level 'INFO'

		try {
			New-ADGroup $MSAName -Path $GroupPath -GroupScope Global -PassThru -Verbose
		} catch {
			Write-Log "Group $MSAName probably already exists. Continuing..." -Level 'Warning'
		}


		try {

			New-ADServiceAccount -Name $MSAName -DNSHostName "$MSAName.$ForestDNSRoot" -PrincipalsAllowedToRetrieveManagedPassword $gMSAGroupServers -Enabled $true -Description 'gMSA account for ADAssessment'

			$Identity = Get-ADComputer -Identity $Servername
			Add-ADComputerServiceAccount -Identity $identity -ServiceAccount $MSANameIdentity


		} catch {
			Write-Log "Failed to create gMSA account: $($_.Exception.Message)" -Level 'Error'
			exit 6
		}
		## Test gMSA account installation in Server

		if (Get-ADServiceAccount -Identity $MSAName) {
			Write-Log "MSA account $MSAName exists in Active Directory." -Level 'INFO'
		} else {
			Write-Log "MSA account $MSAName does not exist in Active Directory." -Level 'Error'
			exit 7
		}

		Write-Log "Add gMSA account $MSAName to 'Enterprise Admins' group." -Level 'INFO'
		try {

			Add-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity
			Write-Log 'MSA account added successfully.' -Level 'INFO'
		} catch {
			Write-Log "Unable to add gMSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'Error'
			exit 8
		}
		Write-Log "Add gMSA account $MSAName to 'Domain Admins' group." -Level 'INFO'
		try {
			Add-ADGroupMember -Identity 'Domain Admins' -Members $MSANameIdentity
			Write-Log 'MSA account added successfully.' -Level 'INFO'
		} catch {
			Write-Log "Unable to add gMSA account to 'Domain Admins': $($_.Exception.Message)" -Level 'Error'
			exit 9
		}

		# Install gMSA account on target server
		foreach ($ServerName in $gMSAGroupServers) {
			Write-Log "Install gMSA account on $ServerName." -Level 'INFO'

			$Return = Invoke-Command -ComputerName $ServerName -ScriptBlock {
				param ($MSANameIdentity, $ServerName)

				try {
					Install-ADServiceAccount -Identity $MSANameIdentity

					exit 0
				} catch {

					exit 1
				}
			}
			if ($Return -eq 1) {
				Write-Log "gMSA account installation failed on $ServerName." -Level 'Error'
			} else {
				Write-Log "gMSA account installed successfully on $ServerName." -Level 'INFO'
			}


			$Return = Invoke-Command -ComputerName $ServerName -ScriptBlock {
				if (Test-ADServiceAccount -Identity $MSANameIdentity) {
					exit 0
				} else {

					exit 1
				}
			}
			if ($Return -eq 1) {
				Write-Log "gMSA account validation failed on $ServerName." -Level 'Error'
				exit 11
			} else {
				Write-Log "gMSA account validated successfully on $ServerName." -Level 'INFO'

				# Refresh the server?s AD group membership without rebooting:
				klist.exe -lh 0 -li 0x3e7 purge


				try {
					Add-ADGroupMember -Identity $MSANameIdentity -Members $ServerName
				} catch {
					Write-Log "Failed to add servers to group $ServerName : $($_.Exception.Message)" -Level 'Error'
				}


			}
		}

	}
	#-----------
	# End Processing
	#-----------
	# Endregion Process
}
#endregion Process
# =============================================================================
#region End
end {
	Write-Log 'Script completed successfully.' -Level 'INFO'
}
#endregion End

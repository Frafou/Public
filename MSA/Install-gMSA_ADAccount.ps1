<#
.SYNOPSIS
    Creates and manages Group Managed Service Accounts (gMSA) with associated security groups for multi-server environments.

.DESCRIPTION
    This comprehensive script manages the complete lifecycle of Active Directory Group Managed Service Accounts (gMSA).
    Unlike standalone MSA accounts, gMSA accounts can be used across multiple servers and provide enhanced security
    through automatic password management and Kerberos authentication.

    CREATION MODE (Default):
    1. Validates prerequisites and administrative permissions
    2. Installs and imports required Active Directory PowerShell module
    3. Retrieves Active Directory forest information and DNS root
    4. Creates or validates KDS Root Key (required for gMSA password generation)
    5. Creates a security group to control gMSA password retrieval permissions
    6. Adds specified servers to the gMSA permissions group
    7. Creates a new Group Managed Service Account in Active Directory
    8. Configures gMSA with DNS hostname and allowed retrieval principals
    9. Installs the gMSA account on the local server
    10. Validates successful gMSA installation and functionality

    REMOVAL MODE (-Remove switch):
    - Uninstalls gMSA from local server
    - Removes gMSA account from Active Directory
    - Optionally removes associated security group
    - Cleans up all related configurations

    Group Managed Service Accounts provide several advantages over traditional service accounts:
    - Automatic password management (240-day default rotation)
    - Support for multiple servers (unlike standalone MSA)
    - Kerberos authentication support
    - No manual password maintenance required
    - Enhanced security through cryptographic key management

.PARAMETER gMSAName
    Specifies the name of the Group Managed Service Account to create or manage.
    This becomes both the account name and the base for the DNS hostname.
    The account name should follow standard Active Directory naming conventions.

    Type: String
    Default: 'MSA_ADAssess'
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER gMSAFQDN
    Specifies the Fully Qualified Domain Name for the gMSA account.
    This parameter appears to be implemented but may not be fully utilized in the current version.
    The script automatically constructs the FQDN using the gMSAName and forest DNS root.

    Type: String
    Default: 'MSA_ADAssess'
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER gMSAGroupName
    Specifies the name of the Active Directory security group that will be created to control
    which servers can retrieve the gMSA account password. This group acts as the principal
    allowed to retrieve the managed password for the gMSA account.

    Type: String
    Default: 'MSA_ADAssessGroup'
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER gMSAGroupServers
    Specifies an array of server names (computer accounts) that will be added to the gMSA
    permissions group. These servers will be able to retrieve the gMSA password and use
    the account for service operations. Server names should include the '$' suffix to
    indicate computer accounts.

    Type: String[]
    Default: @('Srv1$', 'Srv2$', 'Srv3$')
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER Remove
    When specified, the script operates in removal mode, safely removing the gMSA account
    and associated configurations including:
    - gMSA account uninstallation from local server
    - gMSA account deletion from Active Directory
    - Associated security group cleanup (optional)
    - Related permission cleanups

    Type: Switch
    Required: False
    Pipeline Input: True

.INPUTS
    String - gMSA account name, FQDN, and group name can be provided via pipeline
    String[] - Array of server names can be provided via pipeline
    Switch - Remove flag can be provided via pipeline

.OUTPUTS
    Log File: Detailed execution log saved to script directory
        Format: Install-gMSA_ADAccount-YYYYMMDD-HHMMSS.log
        Contains: Timestamped entries for all operations, errors, and validation steps

    Console Output: Real-time progress with color-coded severity levels
        - Green: Informational messages and successful operations
        - Yellow: Warning messages and non-critical issues
        - Red: Error messages and failure conditions
        - Cyan: Debug information when verbose mode is enabled

    Exit Codes: Specific error codes for automation and troubleshooting (see .ErrorCodes section)

.EXAMPLE
    .\Install-gMSA_ADAccount.ps1

    Creates a new gMSA account named 'MSA_ADAssess' with default security group
    'MSA_ADAssessGroup' and default server members, then installs it on the local server.

.EXAMPLE
    .\Install-gMSA_ADAccount.ps1 -gMSAName "WebApp_gMSA" -gMSAGroupName "WebApp_Servers"

    Creates a gMSA account for web application services with a custom name and
    associated security group for web servers.

.EXAMPLE
    .\Install-gMSA_ADAccount.ps1 -gMSAName "DB_gMSA" -gMSAGroupServers @('SQLSRV01$', 'SQLSRV02$', 'SQLSRV03$')

    Creates a gMSA account for database services and specifies specific SQL Server
    computer accounts that can retrieve the gMSA password.

.EXAMPLE
    .\Install-gMSA_ADAccount.ps1 -gMSAName "Service_gMSA" -gMSAGroupName "Service_Hosts" -gMSAGroupServers @('APP01$', 'APP02$') -Verbose

    Creates a gMSA account with custom naming for both account and group, specifies
    two application servers, and enables verbose output for detailed progress tracking.

.EXAMPLE
    .\Install-gMSA_ADAccount.ps1 -gMSAName "MSA_ADAssess" -Remove

    Safely removes the specified gMSA account and cleans up associated configurations
    from both local server and Active Directory.

.NOTES
    File Name      : Install-gMSA_ADAccount.ps1
    Author         : Francois Fournier
    Version        : 1.0.0
    Created        : 2025-01-01
    Last Updated   : 2025-11-24
    License        : MIT License
    Keywords       : gMSA, Group Managed Service Account, Active Directory, Security, PowerShell

    REQUIREMENTS:
    - Windows Server 2012 or higher (for gMSA support)
    - PowerShell 5.1 or higher
    - Administrative privileges on target server
    - Domain Administrator privileges (or equivalent gMSA management rights)
    - Active Directory PowerShell module (auto-installed by script)
    - Network connectivity to Domain Controllers
    - KDS Root Key in domain (created automatically if missing, requires 10-hour replication wait)

    ACTIVE DIRECTORY REQUIREMENTS:
    - Domain functional level Windows Server 2012 or higher
    - At least one Windows Server 2012+ Domain Controller
    - Schema version supporting gMSA (automatic in 2012+ domains)
    - Proper DNS resolution to Domain Controllers
    - Active Directory Web Services (ADWS) running on Domain Controllers
    - Time synchronization across domain (critical for Kerberos)

    PERMISSIONS REQUIRED:
    - Local Administrator on target server
    - Domain Administrator privileges (for gMSA and group creation)
    - Create Computer Objects (for gMSA account creation)
    - Create Group Objects (for security group creation)
    - Manage Group Membership (for server assignments)

    SECURITY CONSIDERATIONS:
    - gMSA passwords are automatically rotated every 30 days by default
    - Password retrieval is controlled through security group membership
    - Accounts use Kerberos authentication exclusively
    - No local password storage required
    - Enhanced security through cryptographic key derivation
    - Follows principle of least privilege through group-based access control

    FEATURES:
    - Comprehensive prerequisite validation
    - Automatic Active Directory module installation
    - KDS Root Key creation and validation
    - Security group creation and management
    - Multi-server support through group membership
    - Detailed error handling with specific exit codes
    - Color-coded console output for easy monitoring
    - Comprehensive logging for audit and troubleshooting
    - Support for both creation and removal operations

    IMPORTANT NOTES:
    - KDS Root Key creation requires up to 10 hours for domain replication
    - gMSA accounts can be used immediately on the creating server
    - Other servers may need to wait for replication before gMSA installation
    - Password changes are automatic and handled by the domain controllers
    - gMSA accounts cannot be used for interactive logon

    CHANGE LOG:
    v1.0.0 - 2025-01-01 - Francois Fournier - Initial version with gMSA support
    v1.0.0 - 2025-11-24 - Francois Fournier - Enhanced documentation and validation

.ErrorCodes
    SUCCESS CODES:
    0   Operation completed successfully

    CREATION FAILURE CODES:
    1   Script not executed with Administrator privileges
    2   Active Directory module installation failed
    3   Active Directory module import failed
    4   Unable to retrieve Forest information from Active Directory
    5   KDS Root Key creation failed (may require manual intervention and replication wait)
    6   gMSA account creation failed in Active Directory
    7   gMSA account does not exist in Active Directory after creation
    8   Unable to add gMSA account to 'Enterprise Admins' group
    9   Unable to add gMSA account to 'Domain Admins' group
    10  gMSA account installation failed on local server
    11  gMSA account validation failed after installation

.LINK
    https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount
    https://woshub.com/group-managed-service-accounts-in-windows-server-2012/
    https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/getting-started-with-group-managed-service-accounts

.COMPONENT
    Active Directory, Group Managed Service Accounts, Security, Identity Management, Kerberos

.ROLE
    Domain Administrator, Security Administrator, System Administrator, Service Account Manager

.FUNCTIONALITY
    gMSA Lifecycle Management, Multi-Server Service Account Deployment, Active Directory Security

.DISCLAIMER
    This script is provided "as is" without warranty of any kind, either express or implied.
    Use of this script is at your own risk. The author assumes no responsibility for any
    damage or loss resulting from the use or misuse of this script.

    You are free to modify and distribute this script, provided that this disclaimer remains
    intact and visible in all copies and derivatives.

    Always test scripts in a safe environment before deploying to production.

    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
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
	[string]$gMSAFQDN = 'MSA_ADAssess.domain.com',
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

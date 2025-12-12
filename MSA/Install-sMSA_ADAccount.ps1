<#
.SYNOPSIS
    Creates, configures, and manages Active Directory Managed Service Accounts (MSA) for On-Demand Assessment services.

.DESCRIPTION
    This comprehensive script manages the complete lifecycle of Active Directory standalone Managed Service Accounts (sMSA).
    It performs the following operations:

    CREATION MODE (Default):
    1. Validates prerequisites and administrative permissions
    2. Installs and imports required Active Directory PowerShell module
    3. Creates KDS Root Key if not present (required for MSA functionality)
    4. Creates a new standalone Managed Service Account in Active Directory
    5. Configures the MSA account with appropriate computer restrictions
    6. Installs the MSA account on the target server
    7. Optionally adds MSA to required groups for Active Directory or Exchange On-Demand Assessment
    8. Grants necessary local rights including "Log on as a Batch Job"
    9. Adds MSA to local Administrators group for assessment operations

    REMOVAL MODE (-Remove switch):
    - Safely removes MSA account from all groups and local configurations
    - Uninstalls MSA from the local server
    - Removes MSA account from Active Directory

    The script is specifically designed for Microsoft On-Demand Assessment services but can be adapted
    for general MSA deployment scenarios. It includes comprehensive error handling, detailed logging,
    and validation at each step to ensure successful MSA deployment.

.PARAMETER MSAName
    Specifies the name of the Managed Service Account to create or manage.
    The MSA name must be 15 characters or less due to Active Directory constraints.
    The script automatically appends '$' for internal operations but displays the friendly name.

    Type: String
    Default: 'MSA_ADAssess'
    Required: False
    Pipeline Input: True (by property name)

.PARAMETER Remove
    When specified, the script operates in removal mode, safely removing the MSA account
    and all associated configurations including:
    - Group memberships (Enterprise Admins, Domain Admins, Organization Management)
    - Local Administrator group membership
    - Local user rights assignments
    - MSA installation from local server
    - MSA account deletion from Active Directory

    Type: Switch
    Required: False
    Pipeline Input: True

.PARAMETER AD_ODA
    When specified, adds the MSA account to required groups for Active Directory On-Demand Assessment:
    - Enterprise Admins group (for comprehensive AD access)
    - Domain Admins group (for domain-level operations)

    This parameter enables the MSA account to perform comprehensive Active Directory assessments
    including schema analysis, security configuration review, and permission auditing.

    Type: Switch
    Required: False
    Pipeline Input: True

.PARAMETER EX_ODA
    When specified, adds the MSA account to required groups for Exchange On-Demand Assessment:
    - Organization Management group (Exchange administrative access)
    - Additional Exchange-specific permissions as needed

    This parameter enables the MSA account to perform Exchange Server assessments including
    configuration analysis, security review, and compliance checking.

    Type: Switch
    Required: False
    Pipeline Input: True

.INPUTS
    String - MSA account name can be provided via pipeline
    Switch - Operation mode and group membership flags can be provided via pipeline

.OUTPUTS
    Log File: Detailed execution log saved to script directory
        Format: Install-sMSA_ADAccount-YYYYMMDD-HHMMSS.log
        Contains: Timestamped entries for all operations, errors, and validation steps

    Console Output: Real-time progress with color-coded severity levels
        - Green: Informational messages and successful operations
        - Yellow: Warning messages and non-critical issues
        - Red: Error messages and failure conditions
        - Cyan: Debug information when verbose mode is enabled

    Exit Codes: Specific error codes for automation and troubleshooting (see .ErrorCodes section)

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1

    Creates a new MSA account named 'MSA_ADAssess' with basic configuration,
    installs it on the local server, and adds to local Administrators group.

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1 -MSAName "MSA_ExchangeAssess" -EX_ODA

    Creates a new MSA account named 'MSA_ExchangeAssess' and configures it
    for Exchange On-Demand Assessment with Organization Management permissions.

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1 -MSAName "MSA_ADAssess" -AD_ODA

    Creates a new MSA account named 'MSA_ADAssess' and configures it
    for Active Directory On-Demand Assessment with Enterprise and Domain Admin permissions.

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1 -MSAName "MSA_ADAssess" -AD_ODA -EX_ODA

    Creates a comprehensive MSA account configured for both Active Directory
    and Exchange On-Demand Assessments with full administrative permissions.

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1 -MSAName "MSA_ADAssess" -Remove

    Safely removes the specified MSA account and all associated configurations
    from local server, groups, and Active Directory.

.EXAMPLE
    .\Install-sMSA_ADAccount.ps1 -Verbose

    Creates MSA account with detailed verbose output showing all validation
    steps, Active Directory operations, and configuration changes.

.NOTES
    File Name      : Install-sMSA_ADAccount.ps1
    Author         : Francois Fournier
    Version        : 1.2
    Created        : 2025-01-01
    Last Updated   : 2025-11-24
    License        : MIT License
    Keywords       : MSA, Managed Service Account, Active Directory, On-Demand Assessment, PowerShell

    REQUIREMENTS:
    - Windows Server 2012 R2 or higher (for MSA support)
    - PowerShell 5.1 or higher
    - Administrative privileges on target server
    - Domain Administrator privileges (or equivalent MSA management rights)
    - Active Directory PowerShell module (auto-installed by script)
    - Network connectivity to Domain Controllers
    - KDS Root Key in domain (created automatically if missing)

    ACTIVE DIRECTORY REQUIREMENTS:
    - Domain functional level Windows Server 2012 or higher
    - At least one Windows Server 2012+ Domain Controller
    - Proper DNS resolution to Domain Controllers
    - Active Directory Web Services (ADWS) running on Domain Controllers

    PERMISSIONS REQUIRED:
    - Local Administrator on target server
    - Domain Administrator privileges (for MSA creation and group management)
    - Create Computer Objects (for MSA account creation)
    - Manage Group Membership (for assessment group assignments)

    SECURITY CONSIDERATIONS:
    - MSA accounts provide enhanced security over traditional service accounts
    - Passwords are automatically managed by Active Directory
    - Account is restricted to specified computer(s)
    - Regular password rotation handled by domain controllers
    - Follows principle of least privilege when possible

    FEATURES:
    - Comprehensive prerequisite validation
    - Automatic Active Directory module installation
    - KDS Root Key creation and validation
    - Detailed error handling with specific exit codes
    - Color-coded console output for easy monitoring
    - Comprehensive logging for audit and troubleshooting
    - Support for both creation and removal operations
    - Flexible group membership configuration

    CHANGE LOG:
    v1.0 - 2025-01-01 - Francois Fournier - Initial version
    v1.1 - 2025-01-01 - Francois Fournier - Added AD_ODA and EX_ODA parameters
    v1.2 - 2025-01-01 - Francois Fournier - Added domain name support, local admin group membership
    v1.2 - 2025-11-24 - Francois Fournier - Enhanced documentation and error handling

.ErrorCodes
    SUCCESS CODES:
    0   Operation completed successfully

    CREATION FAILURE CODES:
    1   MSA name length exceeded 15 characters (Active Directory limitation)
    2   Script not executed with Administrator privileges
    3   Failed to install Active Directory PowerShell module
    4   Failed to import Active Directory PowerShell module
    5   Failed to retrieve Domain Controller information
    6   Failed to create or validate KDS Root Key
    7   Failed to create MSA account in Active Directory
    8   Failed to add host computer to MSA account restrictions
    9   Failed to locate the MSA account in Active Directory after creation
    10  Failed to add MSA account to 'Enterprise Admins' group
    11  Failed to add MSA account to 'Domain Admins' group
    12  Failed to add MSA account to Exchange 'Organization Management' group
    13  Failed to install the MSA account on local server
    14  MSA account validation failed after installation
    15  Failed to grant 'Log on as a Batch Job' user right
    16  Failed to add MSA account to local Administrators group
    17  Failed to verify MSA account in local Administrators group

    REMOVAL FAILURE CODES:
    51  Failed to revoke 'Log on as a Batch Job' user right
    52  Failed to uninstall ADServiceAccount from local server
    53  Failed to remove MSA account from Active Directory
    54  Failed to remove MSA account from 'Enterprise Admins' group
    55  Failed to remove MSA account from 'Domain Admins' group
    56  Failed to remove MSA account from Exchange 'Organization Management' group
    57  Failed to remove MSA account from local Administrators group

.LINK
    https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
    https://docs.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount
    https://woshub.com/group-managed-service-accounts-in-windows-server-2012/
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

.COMPONENT
    Active Directory, Managed Service Accounts, Security, Identity Management

.ROLE
    Domain Administrator, Security Administrator, System Administrator

.FUNCTIONALITY
    MSA Lifecycle Management, Active Directory Security, Service Account Automation

.DISCLAIMER
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
		Write-Log 'Add-RightToUser' -Level 'INFO'
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
			#gpupdate /force
			try {
				Invoke-GPUpdate -Force -ErrorAction Stop
			}	catch {
				Write-Log 'Failed to update Group Policy' -Level 'ERROR'
			}

			try {
				Remove-Item $tmp* -ea 0
			}	catch {
				Write-Log 'Failed to cleanup files' -Level 'ERROR'
			}

		}
	}

	function Remove-RightFromUser([string] $Username, $Right) {
		<# Add error handling#>
		Write-Log 'Remove-RightFromUser' -Level 'WARNING'
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

			Write-Log 'Importing new policy on temp database' -Level 'INFO'
			secedit /import /cfg $TempConfigFile /db $TempDbFile

			Write-Log 'Applying new policy to machine' -Level 'INFO'
			secedit /configure /db $TempDbFile /cfg $TempConfigFile

			Write-Log 'Updating policy' -Level 'INFO'
			gpupdate /force

			Remove-Item $tmp* -ea 0
		} else {
			Write-Log "MSA $Username did not have right" -Level 'INFO'
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
	Clear-Host
	Write-Log '------------------------------------' -Level 'INFO'
	Write-Log 'Script started.' -Level 'INFO'


	if ($MSAName.Length -gt 15) {
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
		Write-Log 'Failed to import the Active Directory module. Please check the installation.' -Level 'ERROR'
		exit 4
	}

	$DomainFQDN = (Get-ADDomain).Forest
	$DomainName = (Get-ADDomain).Name

	if ($null -eq $DomainFQDN) {
		Write-Log 'Failed to retrieve Domain information from Active Directory.' -Level 'ERROR'
		exit 5
	} else {
		Write-Log "Domain retrieved: $DomainName" -Level 'INFO'
		Write-Log "Domain FQDN: $DomainFQDN" -Level 'INFO'
	}

	if ($Remove) {
		Write-Log "Validating MSA '$MSAName' in the local Administrators group." -Level 'INFO'
		# Check if the MSA exists locally
		$userExists = Get-LocalGroupMember -Name 'Administrators' -Member "$DomainName\$MSANameIdentity" -ErrorAction SilentlyContinue
		if ($userExists ) {
			Write-Log "MSA '$MSAName' exists in the local Administrators group." -Level 'INFO'
			#Remove the MSA to the Administrators group
			Write-Log "Removing MSA '$MSAName' in the local Administrators group." -Level 'INFO'
			try {
				Remove-LocalGroupMember -Group 'Administrators' -Member $MSANameIdentity -ErrorAction Stop
				Write-Log "MSA '$MSAName' has been removed from the local Administrators group." -Level 'INFO'
			} catch {
				Write-Log "$($_.Exception.Message)" -Level 'ERROR'
				#exit 57
			}
		} else {
			Write-Log "Failed to locate the MSA '$MSAName' in the local Administrators Group. Check the name." -Level 'ERROR'
			#exit 17
		}


		# Remove from groups if required
		if ($AD_ODA) {
			Write-Log "Removing MSA account $MSAName to 'Enterprise Admins' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity 'Enterprise Admins' -Members $MSANameIdentity -Confirm:$false
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Failed to add MSA account to 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 10
			}

			Write-Log "Removing MSA account $MSAName to 'Domain Admins' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity 'Domain Admins' -Members $MSANameIdentity -Confirm:$false
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Failed to add MSA account from 'Domain Admins': $($_.Exception.Message)" -Level 'ERROR'
				exit 11
			}
		}
		if ( $EX_ODA) {
			Write-Log "Removing MSA account $MSAName from the Exchange 'Organization Management' group." -Level 'INFO'
			try {
				Remove-ADGroupMember -Identity 'Organization Management' -Members $MSANameIdentity -Confirm:$false
				Write-Log 'MSA account removed successfully.' -Level 'INFO'
			} catch {
				Write-Log "Failed to remove MSA account from the Exchange 'Organization Management' group: $($_.Exception.Message)" -Level 'ERROR'
				exit 12
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
			#exit 51
		}

		Write-Log "Uninstall ADServiceAccount $MSANameIdentity." -Level 'INFO'
		try {
			Uninstall-ADServiceAccount -Identity $MSANameIdentity
			Write-Log 'ADServiceAccount removed successfully.' -Level 'INFO'
		} catch {
			Write-Log "Failed to remove ADServiceAccount: $($_.Exception.Message)" -Level 'ERROR'
			#exit 52
		}

		Write-Log "Removing MSA account $MSAName." -Level 'INFO'
		try {
			Remove-ADServiceAccount -Identity $MSAName -Confirm:$false
			Write-Log "MSA account $MSAName removed successfully." -Level 'INFO'
		} catch {
			Write-Log "Failed to remove MSA account: $($_.Exception.Message)" -Level 'ERROR'
			#exit 53
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

		Write-Log "ADServiceAccount -Name $MSAName." -Level 'INFO'
		try {

			New-ADServiceAccount -DisplayName $MSAName -Name $MSAName -RestrictToSingleComputer -Enabled $true -Description "MSA account for ODA Assessment on $ServerName"
			Write-Log "MSA account $MSAName created successfully." -Level 'INFO'

			Write-Log "Adding MSA account '$MSAName' to local server." -Level 'INFO'
			$Identity = Get-ADComputer -Identity $Servername
			try {
				Add-ADComputerServiceAccount -Identity $identity -ServiceAccount $MSANameIdentity
				Write-Log "Added Host $Servername to MSA account $MSAName." -Level 'INFO'
			} catch {
				Write-Log "Failed to add Host $Servername to MSA account: $($_.Exception.Message)" -Level 'ERROR'
				exit 8
			}


		} catch {
			Write-Log "Failed to create MSA account: $($_.Exception.Message)" -Level 'ERROR'
			exit 7
		}
		## Test MSA account installation in Server

		if (Get-ADServiceAccount -Identity $MSAName) {
			Write-Log "MSA account $MSAName exists in Active Directory." -Level 'INFO'
		} else {
			Write-Log "Failed to locate the MSA account $MSAName in Active Directory." -Level 'ERROR'
			exit 9
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
				Write-Log "Failed to add MSA account from 'Enterprise Admins': $($_.Exception.Message)" -Level 'ERROR'
				#exit 54
			}
			Write-Log "Add MSA account $MSAName to 'Domain Admins' group." -Level 'INFO'
			try {
				Add-ADGroupMember -Identity 'Domain Admins' -Members $MSANameIdentity
				Write-Log 'MSA account added successfully.' -Level 'INFO'
			} catch {
				Write-Log "Failed to add MSA account from 'Domain Admins': $($_.Exception.Message)" -Level 'ERROR'
				#exit 55
			}
		}
		<#
		Exchange On-Demand Assessment
		#>
		if ($EX_ODA) {
			Write-Log "Add MSA account $MSAName to the Exchange 'Organization Management' group." -Level 'INFO'
			try {

				Add-ADGroupMember -Identity 'Organization Management' -Members $MSANameIdentity
				Write-Log 'MSA account added successfully.' -Level 'INFO'
			} catch {
				Write-Log "Failed to add MSA account from the Exchange 'Organization Management' group: $($_.Exception.Message)" -Level 'ERROR'
				#exit 56
			}

		}
		<#
		Add to local Admin group
		#>
		# Add a MSA to the local Administrators group
		# Works for local accounts and Microsoft accounts
		# Requires running PowerShell as Administrator
		# Pause
		Write-Log "Adding MSA '$MSAName' to the local Administrators group." -Level 'INFO'
		try {

			# Check if the MSA exists locally
			$userExists = Get-ADServiceAccount -Identity $MSANameIdentity -ErrorAction SilentlyContinue
			if (-not $userExists ) {
				throw "MSA '$MSAName' does not exist. Check the name."
			}

			# Add the MSA to the Administrators group
			Add-LocalGroupMember -Group 'Administrators' -Member "$DomainName\$MSANameIdentity" -ErrorAction Stop

			Write-Log "MSA '$MSAName' has been added to the local Administrators group." -Level 'INFO'
		} catch {
			Write-Log "$($_.Exception.Message)" -Level 'ERROR'
			exit 16
		}


		<#
		Logon as a batch job Right
		#>

		Write-Log 'Adding Logon as a batch job Right' -Level 'INFO'
		try {
			Add-RightToUser -Username $MSANameIdentity -Right 'SeBatchLogonRight'
			Write-Log 'Logon as a batch Job Right Added' -Level 'INFO'
		} catch {

			Write-Log "Failed to add Logon as a batch Job right: $($_.Exception.Message)" -Level 'ERROR'
			exit 15
		}

		Write-Log "Install MSA account on $ServerName." -Level 'INFO'
		try {
			Install-ADServiceAccount -Identity $MSANameIdentity
			Write-Log "MSA account installed successfully on $ServerName." -Level 'INFO'
		} catch {
			Write-Log "Failed to install MSA account: $($_.Exception.Message)" -Level 'ERROR'
			exit 13
		}

		Write-Log 'Testing MSA account' -Level 'INFO'
		if (Test-ADServiceAccount -Identity $MSANameIdentity) {
			Write-Log "MSA account $MSAName is valid." -Level 'INFO'
		} else {
			Write-Log "MSA account $MSAName is not valid." -Level 'ERROR'
			exit 14
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
	Write-Log '------------------------------------' -Level 'INFO'
	Write-Host "Log file created at: $LogFile" -ForegroundColor Green

}
#endregion End

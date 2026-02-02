<#
	.SYNOPSIS
	ACTT Tool Extraction Code for Windows Server Analysis of Active Directory

	.DESCRIPTION
 	ACTT Tool Extraction Code for Windows Server Analysis of Active Directory
	------------------------------------------------------------------------------------
	The purpose of this "read only" script is to download data that can be analyzed as part of our audit.
	We expect that you will follow your company's regular change management policies and procedures prior to running the script.
	To the extent permitted by law, regulation and our professional standards, this script is provided "as is", without any warranty, and the Deloitte Network and its contractors will not be liable for any damages relating to this script or its use.
	As used herein, "we" and "our" refers to the Deloitte Network entity that provided the script to you, and the "Deloitte Network" refers to Deloitte Touche Tohmatsu Limited ("DTTL"), the member firms of DTTL, and each of their affiliates and related entities.

	.PARAMETER  ForestFQDN
	FQDN of forest to Query.
	Default to loacal domain

	.PARAMETER  ComputerName
	Name of computer to query	FQDN of forest to Query.
	Default to local server

	.PARAMETER  Path
	Path to output folder
	Default to local folder

	.EXAMPLE
	ACCT_Windows_Script.ps1

		.EXAMPLE
	ACCT_Windows_Script.ps1 -ForestFQDN "Domain.com"

		.EXAMPLE
	ACCT_Windows_Script.ps1 -ComputerName "Servername"

		.EXAMPLE
	ACCT_Windows_Script.ps1 -path "c:\Output"

	.INPUTS
	None

	.OUTPUTS
	Outputs multiple files (ACCT, Log and HTML Files) to the specified folder.

	.NOTES
  REVISION HISTORY:
---------------------------------------------------------------------------------
Date(DD/MM/YYYY)		Responsible							Activity
------------------------------------------------------------------------------------
2018-01-26		Ramakrishna, Shashank				Code Created
2019-10-25		Ramakrishna, Shashank				This script is an integrated version of R16 scripts of Windows and includes all bug fixes which were accomodated earlier
2021-01-10		Ramakrishna, Shashank				This script Updated for supporting Multi-Language support bug fix #2380
2021-10-20		Ramakrishna, Shashank 			Script added to extract data related to OU. Updated version to 18.1
2022-04-22		Antony, Godwin				    	Script updated to version 19.0 and hashed out ACTTDataLog message for OuPermissions extraction.
2024-110-04		Kosuri, Tarun Sai			    	Updated GroupMembers extraction code to reduce the extraction time
2023-04-04    Kosuri, Tarun Sai           Updated OUs extraction code to reduce the extraction time
2023-05-05    Kosuri, Tarun Sai           Added code to extract domain groupmembers informaion when executed on non domain controller.
2023-06-05    Kosuri, Tarun Sai           Script updated to rename GPOReportAll.html wirh html extension to GPOReportAll.html.txt PB#2795.
20203-08-22		Kosuri, Tarun Sai					  Script updated to handle AccountExpirationDate exceeding the limit of FromFileTime date PB# 1532470.
2024-09-09		Fournier, Francois				  Script updated to provide the same Global Delimiter to all output file
2024-09-09		Fournier, Francois				  Script updated to provide provide correct name to HTML filer

#>
#region Parameters
[CmdletBinding()]
param(
	[Parameter(
		Mandatory = $false)]
	[String]$ForestFQDN = (Get-WmiObject win32_computersystem).Domain,

	[Parameter(
		Mandatory = $false)]
	[String]$ComputerName = (Get-WmiObject win32_computersystem).Name,

	[Parameter(
		Mandatory = $false)]
	[String]$Path = (Get-Location))

#endregion Parameters

#region Script Execution Code
<#
	This region of Script Code Sets Script Execution Options
	If the -Debug or -Verbose Common Parameters were Used.
	Needs to be at the top to set the Preferences before any Main Logic
	Code is run to have the options work correctly.

	Note:
		Use Set-StrictMode during Debugging Only!
		Comment out before releasing code to production.
		This will allow Non-Terminating Exceptions to be handled
		and allow the script to continue.
#>
$ScriptStartTime = Get-Date
Set-StrictMode -Version Latest

# Configure Verbose and Debugging Options
if ($MyInvocation.BoundParameters.ContainsKey('Verbose')) {
	$VerbosePreference = 'Continue'
	Write-Verbose "Verbose Option Set: `$VerbosePreference Value: $VerbosePreference"
}
if ($MyInvocation.BoundParameters.ContainsKey('Debug')) {
	$DebugPreference = 'Continue'
	Write-Debug "Debug Option Set: `$DebugPreference Value: $DebugPreference `n`n"
}
#endregion  Script Execution Code

#region Global Variables
$Delim = ';' #'|^|'
$ScriptVersion = '20.1p'
#$TimeDate = get-date -format 'MM/dd/yyyy hh:mm:ss.fff tt'
#$ErrorList = @()
#$FilePermissions = @{ 'Path' = ''; 'AccessControlType' = ''; 'FileSystemRights' = ''; 'IdentityReference' = '' }
#$FilePermissionsList = @()
#endregion Global Variables

# Leave 2 Empty Lines before Declaring Functions for Comment Based Help to work properly


#region Functions

Function Get-ServerAuditPolicy {
	<#
	.SYNOPSIS
		List audit policy on  DC - auditPolicy.actt

	.DESCRIPTION
		File: auditPolicy.actt
		NameSpace: '\root\rsop\computer'
		Query: 'SELECT * FROM RSOP_AuditPolicy'
		Report Fields: 'Category', 'Precedence', 'Failure', 'Success'

	.PARAMETER  Server
	server

	.PARAMETER  Path
	Path of output file

	.EXAMPLE


	.INPUTS
	None


	.OUTPUTS
	none


	.NOTES


	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>

	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#
	Try {
		Write-ACTTDataLog -Message 'Get audit policy - auditPolicy.actt'

		$colAuditPolicies = @()
		$WMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT * FROM RSOP_AuditPolicy' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$AuditPolicies = @('AuditPrivilegeUse', 'AuditDSAccess', 'AuditAccountLogon', 'AuditObjectAccess', 'AuditAccountManage',
			'AuditLogonEvents', 'AuditProcessTracking', 'AuditSystemEvents', 'AuditPolicyChange')
		$notDefinedvalue = $null
		If ($null -ne $WMIQuery) {
			ForEach ($Policy in $AuditPolicies) {
				$notDefinedvalue = $Policy
				ForEach ($item in $WMIQuery) {
					If ($Policy -eq $item.Category) {
						$objTemp = [PSCustomObject] @{
							'Category'   = $item.Category
							'Precedence' = $item.Precedence
							'Failure'    = $item.Failure
							'Success'    = $item.Success
						}

						# Add psCustomObject to Collection
						$colAuditPolicies += $objTemp
						$notDefinedvalue = $null
					}

				}

				if ($null -ne $notDefinedvalue) {
					$objTemp = [PSCustomObject] @{
						'Category'   = $Policy
						'Precedence' = 'Not Defined'
						'Failure'    = 'Not Defined'
						'Success'    = 'Not Defined'
					}

					# Add psCustomObject to Collection
					$colAuditPolicies += $objTemp
				}


			}
		} else {
			foreach ($Policy in $AuditPolicies) {
				$objTemp = [PSCustomObject] @{
					'Category'   = $Policy
					'Precedence' = 'Not Defined'
					'Failure'    = 'Not Defined'
					'Success'    = 'Not Defined'
				}
				$colAuditPolicies += $objTemp
			}

		}

		Write-Host 'Exporting audit policy - auditPolicy.actt'
		Write-ACTTDataLog -Message "`tExporting audit policy - auditPolicy.actt"
		Write-ActtFile -Data $colAuditPolicies -Path $(Join-Path $Path 'auditPolicy.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to list audit policy on local DC - auditPolicy.actt. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List audit policy on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-ServerQuickFixes {
	<#
	.SYNOPSIS
		List all quickfixes - quickfixes.actt

	.DESCRIPTION
		NameSpace: "\root\cimv2"
		Query: 'SELECT * FROM Win32_QuickFixEngineering'
		Report Fields: 'Caption', 'CSName', 'Description', 'FixComments', 'HotFixID', 'InstallDate', 'InstalledBy', 'InstalledOn', 'Name', 'ServicePackInEffect', 'Status'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path of output file

	.INPUTS
	none

	.OUTPUTS
	File: quickfixes.actt

	.NOTES

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>

	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all quickfixes - quickfixes.actt'

		$colQuickFixes = @()
		$WMIQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_QuickFixEngineering' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError

		If ($null -ne $WMIQuery) {
			ForEach ($item in $WMIQuery) {
				$objTemp = [PSCustomObject] @{
					'Caption'             = $item.Caption
					'CSName'              = $item.CSName
					'Description'         = $item.Description
					'FixComments'         = $item.FixComments
					'HotFixID'            = $item.HotFixID
					'InstallDate'         = $item.InstallDate
					'InstalledBy'         = $item.InstalledBy
					'InstalledOn'         = $item.InstalledOn
					'Name'                = $item.Name
					'ServicePackInEffect' = $item.ServicePackInEffect
					'Status'              = $item.Status
				}

				# Add psCustomObject to Collection
				$colQuickFixes += $objTemp
			}
		} else {
			$objTemp = [PSCustomObject] @{
				'Caption'             = 'Not available'
				'CSName'              = 'Not available'
				'Description'         = 'Not available'
				'FixComments'         = 'Not Available'
				'HotFixID'            = 'Not Available'
				'InstallDate'         = 'Not Available'
				'InstalledBy'         = 'Not Available'
				'InstalledOn'         = 'Not Available'
				'Name'                = 'Not Available'
				'ServicePackInEffect' = 'Not Available'
				'Status'              = 'Not Available'
			}
			$colQuickFixes += $objTemp
		}


		Write-ACTTDataLog -Message "`tExporting all quickfixes installed - quickfixes.actt"
		Write-Host 'Exporting all quickfixes installed - quickfixes.actt'
		Write-ActtFile -Data $colQuickFixes -Path $(Join-Path $Path 'quickfixes.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to list all quickfixes on local DC - quickfixes.actt. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List all quickfixes Assignments on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-ServerUserRights {
	<#
	.SYNOPSIS
		List all User Rights Assignment on the server - userRights.actt

	.DESCRIPTION
		NameSpace: '\root\rsop\computer'
		Query: 'SELECT UserRight, Precedence, AccountList FROM RSOP_UserPrivilegeRight'
		Report Fields: 'UserRight', 'AccountList', 'Precedence'
		Need Remoting - User Rights Assignment needs to run "locally"

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path of output file

	.INPUTS
	None

	.OUTPUTS
	File: userRights.actt

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>

	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[String]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all User Rights Assignment on Domain Controller - userRights.actt'

		$colUserRightsAssignment = @()
		$WMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT UserRight, Precedence, AccountList FROM RSOP_UserPrivilegeRight' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$UserRights = @('SeNetworkLogonRight', 'SeRemoteInteractiveLogonRight',
			'SeRemoteShutdownPrivilege', 'SeBatchLogonRight', 'SeTcbPrivilege',
			'SeServiceLogonRight', 'SeSecurityPrivilege', 'SeRestorePrivilege',
			'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege')
		$notDefinedvalue = $null
		If ($null -ne $WMIQuery) {
			ForEach ($UserRight in $UserRights) {
				$notDefinedvalue = $UserRight
				ForEach ($item in $WMIQuery) {
					If ($UserRight -eq $item.UserRight) {
						ForEach ($AccountList in $item.AccountList) {
							$objTemp = [PSCustomObject] @{
								'UserRight'   = $item.UserRight
								'AccountList' = $AccountList
								'Precedence'  = $item.Precedence
							}
							$colUserRightsAssignment += $objTemp
						}

						# Add psCustomObject to colFilePermissions

						$notDefinedvalue = $null
					}

				}
				if ($null -ne $notDefinedvalue) {
					$objTemp = [PSCustomObject] @{
						'UserRight'   = $notDefinedvalue
						'AccountList' = 'Not Defined'
						'Precedence'  = 'Not Defined'
					}

					# Add psCustomObject to colFilePermissions
					$colUserRightsAssignment += $objTemp
				}

			}

		} else {
			Foreach ($right in $UserRights) {
				$objTemp = [PSCustomObject] @{
					'UserRight'   = $right
					'AccountList' = 'Not Defined'
					'Precedence'  = 'Not Defined'
				}

				# Add psCustomObject to colFilePermissions
				$colUserRightsAssignment += $objTemp
			}
		}


		Write-ACTTDataLog -Message "`tExporting all User Rights Assingment on Server - userRights.actt"
		Write-Host 'Exporting all User Rights Assingment on Server - userRights.actt'
		Write-ActtFile -Data $colUserRightsAssignment -Path $(Join-Path $Path 'userRights.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to list all User Rights Assignments. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Could not List all User Rights Assignments on $Server")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainComputersAll {
	<#
	.SYNOPSIS
		List all Computer objects in domain - Computers.actt

	.DESCRIPTION
		Report Fields: 'SamAccountName', 'Name', 'Description', 'LastLogon', 'OperatingSystem', 'OperatingSystemVersion', 'OperatingSystemServicePack', 'DNSHostName', 'DistinguishedName'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path of output file

	.INPUTS
	none

	.OUTPUTS
	File: Computers.actt

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all Computer objects in domain - Computers.actt
	Try {
		Write-ACTTDataLog -Message 'Get all Computer objects in domain - Computers.actt'
		Write-Host 'Searching All Computer Objects'
		$AllComputerObjects = Get-ADComputer -Server $Server -Filter * -Properties SamAccountName, Name, Description, LastLogon, OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack, DNSHostName, DistinguishedName -ErrorAction Stop
		$colComputers = @()

		foreach ($Computer in $AllComputerObjects) {
			#Build ComputerObject
			$objComp = [PSCustomObject] @{
				'SamAccountName'             = $Computer.SamAccountName
				'Name'                       = $Computer.Name
				'Description'                = $Computer.Description
				'LastLogon'                  = $Computer.LastLogon
				'OperatingSystem'            = $Computer.OperatingSystem
				'OperatingSystemVersion'     = $Computer.OperatingSystemVersion
				'OperatingSystemServicePack' = $Computer.OperatingSystemServicePack
				'DNSHostName'                = $Computer.DNSHostName
				'DistinguishedName'          = $Computer.DistinguishedName
			}

			# Add objDC to colDCs
			$colComputers += $objComp
		}

		Write-ACTTDataLog -Message "`tExporting All Computer Objects - Computers.actt"
		Write-Host 'Exporting All Computer Objects - Computers.actt'
		Write-ActtFile -Data $colComputers -Path $(Join-Path $Path 'Computers.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all computer objects in the domain. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Computer objects in domain')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-OuPermissions {
	<#
	.SYNOPSIS
		Get's OU permissions for AD audit procedures
	.DESCRIPTION
		Exports a CSV of OU Permissions for AD audit procedures. Does not include permissions for standard AD privileged groups
		or special identities such as "Self" or "CREATOR OWNER".

	.PARAMETER  Domain
	Domain to query

	.PARAMETER  Path
	Path of output file

	.INPUTS
	none

	.OUTPUTS
	File: Computers.actt
	#>
	#region [SCRIPT PARAMETERS] -----------------------------------------------------------------------
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $true)]
		[String]$Domain,
		[Parameter(
			Mandatory = $true)]
		[String]$Path)
	#endregion [SCRIPT PARAMETERS] -----------------------------------------------------------------------
	#region [Initializations] -----------------------------------------------------------------------
	#$ErrorActionPreference = 'SilentlyContinue'
	Try {
		Write-ACTTDataLog -Message 'Get get-OUPermission.actt'

		#endregion [Initializations] -----------------------------------------------------------------------

		#region [Declarations] -----------------------------------------------------------------------

		#$outputFileName = "OU_Permissions" --Prakash
		$dn = $Domain
		Write-ACTTDataLog -Message "`tExporting All OU Permissions - OUPermissions.actt"


		$excludedIdentities = @(
			'Enterprise Admins',
			'Schema Admins',
			'Domain Admins',
			'Administrators',
			'Account Operators',
			'Server Operators',
			'CREATOR OWNER',
			'Self'
		)

		$excludedAccessRights = @(
			'ReadProperty',
			'GenericRead',
			'GenericExecute',
			'ReadProperty, GenericExecute',
			'ReadControl',
			'ListChildren',
			'ListChildren, ReadProperty, ListObject'
		)


		#endregion [Declarations] -----------------------------------------------------------------------

		#region [Functions] -----------------------------------------------------------------------

		#region AD Functions

		function Get-NETBiosName ( $dn, $ConfigurationNC ) {
			<#
	.SYNOPSIS
		Get NetBiosName of computer.
	.DESCRIPTION
		Return netbios name of specified server.
		Wil return an empty value if the server if not identified

	.PARAMETER  DN
	DN to search for

	.PARAMETER  ConfigurationNC
	Nic to search for

	.INPUTS
	none

	.OUTPUTS
	none
	#>
			try {
				$Searcher = New-Object System.DirectoryServices.DirectorySearcher
				$Searcher.SearchScope = 'subtree'
				$Searcher.PropertiesToLoad.Add('nETBIOSName') | Out-Null
				$Searcher.SearchRoot = "LDAP://cn=Partitions,$ConfigurationNC"
				$Searcher.Filter = "(nCName=$dn)"
				$NetBIOSName = ($Searcher.FindOne()).Properties.Item('nETBIOSName')
				Return $NetBIOSName
			} catch {
				Return $null
			}
		}


		function Format-DistinguishedName {
			<#
	.SYNOPSIS
		Get NetBiosName of computer.
	.DESCRIPTION
		Return netbios name of specified server.
		Wil return an empty value if the server if not identified

	.PARAMETER  Path
	DN to search for

	.PARAMETER  Format
	Specify format of output:
	'DistinguishedName', 'CanonicalName'

	.PARAMETER  ExcludeDomain
	[switch] ExcludeDomain

.PARAMETER  ExcludeCN
	[switch] ExcludeCN

	.INPUTS
	none

	.OUTPUTS
	none
	#>
			[CmdletBinding()]
			param (
				# Parameter help description
				[Parameter(ValueFromPipeline)]
				[string[]]
				$Path,

				[Parameter(Mandatory = $false)]
				[ValidateSet('DistinguishedName', 'CanonicalName')]
				[string]
				$Format = 'CanonicalName',

				[switch]
				$ExcludeDomain,

				[switch]
				$ExcludeCN
			)

			begin {

			}

			process {
				$split = $Path.Split(',') |
					#Where-Object { $ExcludeDomain -eq $true -and $_ -notlike 'dn=*'} |
					Where-Object { $ExcludeCN -eq $false -or $_ -notlike 'cn=*' }

				$arr = (@(($split | Where-Object { $_ -notmatch 'DC=' }) | ForEach-Object { $_.Substring(3) }))
				[array]::Reverse($arr)


				$base = $arr -join '/'

				$dn = ($split | Where-Object { $_ -Match 'dc=' } | ForEach-Object { $_.replace('DC=', '') }) -join '.'

				if ($ExcludeDomain -eq $false) {
					$return = $dn + '/' + $base
				}

				Write-Output $return

			}

			end {

			}
		}

		#endregion AD Functions

		#endregion [Functions] -----------------------------------------------------------------------
		#-----------------------------------------[Execution]-----------------------------------------

		# This array will hold the report output.
		#$report = @()
		# Build Output Filename
		$rootDSE = [adsi]'LDAP://RootDSE'
		$configNamingContext = $rootDSE.configurationNamingContext
		$domainD = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
		$domainDN = 'dc=' + $domainD.Name.Replace('.', ',dc=')
		$netBiosName = Get-NETBiosName $domainDN $configNamingContext

		#Write-ACTTDataLog -Message 'Get get-OUPermission.actt -Prakash91'

		# Hide the errors for a couple duplicate hash table keys.
		$schemaIDGUID = @{}
		### NEED TO RECONCILE THE CONFLICTS ###
		$ErrorActionPreference = 'SilentlyContinue'

		try {
			$schemaIDGUID = @{}
			Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object { $schemaIDGUID.add([System.GUID]$_.schemaIDGUID, $_.name) }
			Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object { $schemaIDGUID.add([System.GUID]$_.rightsGUID, $_.name) }

			$ErrorActionPreference = 'Continue'
		} catch {
			Write-ACTTDataLog -Message 'Get get-OUPermission.actt -Exception'

		}


		# Get a list of all OUs.  Add in the root containers for good measure (users, computers, etc.).

		$OUs = @(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)
		$OUs += Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName
		[String]$DomainDN = ''
		#$ForestFQDN.split('.') | %{ $DomainDN="DN=$($_),$DomainDN"}
		$DomainDN = 'DC=' + $ForestFQDN.Replace('.', ',DC=')
		$OUs += Get-ADObject -Server $ComputerName -SearchBase $DomainDN -SearchScope OneLevel -LDAPFilter '(objectClass=container)' | Select-Object -ExpandProperty DistinguishedName

		#$excludedObjectGuids = $excludedIdentities | ForEach-Object { $schemaIDGUID | Where-Object { $_.Value -eq $_ } | Select-Object -Property Key }
		# $lapsAttrGuid = $schemaIDGUID.GetEnumerator() | Where-Object { $_.Value -eq 'ms-Mcs-AdmPwd' }


		$Path = Join-Path $Path 'OUPermissions.actt'
		$Header = "[AccessControlType] NVARCHAR(MAX)$Delim[ActiveDirectoryRights] NVARCHAR(MAX)$Delim[identityName] NVARCHAR(MAX)$Delim[IdentityReference] NVARCHAR(MAX)$Delim[InheritanceFlags] NVARCHAR(MAX)$Delim[InheritanceType] NVARCHAR(MAX)$Delim[inheritedObjectTypeName] NVARCHAR(MAX)$Delim[IsInherited] NVARCHAR(MAX)$Delim[objectTypeName] NVARCHAR(MAX)$Delim[organizationalUnit] NVARCHAR(MAX)$Delim[organizationalUnitCN] NVARCHAR(MAX)$Delim[PropagationFlags] NVARCHAR(MAX)"
		$swriter = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
		$swriter.WriteLine($Header)
		$swriter.Close()

		# Need Guid so we can include earlier in the filter pipleline to optimize processing.
		$lapsAttrGuid = '';

		foreach ($guid in $schemaIDGUID.GetEnumerator()) {
			if ($guid.Value -eq 'ms-Mcs-AdmPwd' ) {
				$lapsAttrGuid = $guid.Key.ToString()
				break
			}
		}

		$i = 0
		$total = $OUs.Count
		$secRemaining = -1
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		$stb = [System.Text.StringBuilder]''

		# Loop through each of the OUs and retrieve their permissions.
		ForEach ($OU in $OUs) {

			$i++
			Write-Progress -Activity 'Exporting OU Permissions' -Status "($i of $total)" -CurrentOperation "Exporting $OU" -PercentComplete ($i / $total * 100) -SecondsRemaining $secRemaining

			$canonicalName = @{label = 'organizationalUnitCN'; expression = { (Format-DistinguishedName -Path $OU) } }
			$ACLs = Get-Acl -Path "AD:\$OU" | Select-Object -ExpandProperty Access | Where-Object({
                           ($_.ActiveDirectoryRights -notin $excludedAccessRights -or $_.objectType.ToString() -eq $lapsAttrGuid) -and ( $_.IdentityReference -notlike 'NT AUTHORITY\*' -and $_.IdentityReference -notlike 'BUILTIN\*' -and $_.identityReference -notlike 'S-1-*' ) }) |
				Select-Object $canonicalName,
				@{name = 'organizationalUnit'; expression = { $OU } }, `
					IdentityReference,
				AccessControlType,
				ActiveDirectoryRights,
				@{name = 'inheritedObjectTypeName'; expression = { $schemaIDGUID[$_.inheritedObjectType] } }, `
				@{name = 'objectTypeName'; expression = { if ($_.objectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {
							'All'
						} Else {
							$schemaIDGUID[$_.objectType]
						} }
				}, `
				@{name = 'identityName'; expression = { if ($_.identityReference -like '*\*') {
 ($_.identityReference).ToString().Split('\')[1]
						} Else {
							$_.identityReference
						} }
				}, `
					InheritanceType,
				InheritanceFlags,
				PropagationFlags,
				IsInherited | Where-Object( { ( $_.identityName -notin $excludedIdentities ) -and ( $_.inheritedObjectTypeName -in 'Computer', 'User', 'Group' -or $null -eq $_.inheritedObjectTypeName ) } )
			[void]$stb.Clear()
			if ($null -eq $ACLs) {
				continue
			}
			ForEach ($Properties in $ACLs) {
				[void]$stb.Append($Properties.AccessControlType).Append("$Delim")
				[void]$stb.Append($Properties.ActiveDirectoryRights).Append("$Delim")
				[void]$stb.Append($Properties.identityName).Append("$Delim")
				[void]$stb.Append($Properties.IdentityReference).Append("$Delim")
				[void]$stb.Append($Properties.InheritanceFlags).Append("$Delim")
				[void]$stb.Append($Properties.InheritanceType).Append("$Delim")
				[void]$stb.Append($Properties.inheritedObjectTypeName).Append("$Delim")
				[void]$stb.Append($Properties.IsInherited).Append("$Delim")
				[void]$stb.Append($Properties.objectTypeName).Append("$Delim")
				[void]$stb.Append($Properties.organizationalUnit).Append("$Delim")
				[void]$stb.Append($Properties.organizationalUnitCN).Append("$Delim")
				[void]$stb.Append($Properties.PropagationFlags).AppendLine()
			}
			# $stb.ToString() | Out-File -Append -FilePath $(Join-Path $Path 'OUPermissions.actt')
			$swriter = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
			$swriter.WriteLine($stb.ToString().Trim())
			$swriter.Close()
			[void]$stb.Clear()
			[System.GC]::Collect()
			[System.GC]::WaitForPendingFinalizers()

			$secRemaining = [Math]::Round(($sw.Elapsed.Seconds / $i) * ($total - $i) )
		}
		Write-ACTTDataLog -Message "`tExporting Permissions - OUPermissions.actt"
		Write-Host 'Exporting Permissions - OUPermissions.actt'
	} Catch {
		#Some error occurred attempting to List all computer objects in the domain. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all OU Permissions')
		$swExceptionLog.WriteLine($Error[0])

	}
}


Function Get-DCsInDomain {
	<#
	.SYNOPSIS
		Get DC's in Domain
	.DESCRIPTION
		Exports a list of Domain Controlers".

	.PARAMETER  Domain
	Domain

	.PARAMETER  Path
	Path of output file

	.INPUTS
	none

	.OUTPUTS
	File: DomainControllers.actt

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	# Function uses a Domain object from a Forest Object
	[CmdletBinding()]
	param (

		[Parameter(
			Mandatory = $false)]
		[Object]$Domain,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)
	Try {
		Write-ACTTDataLog -Message 'Get Domains Controllers in the Domain - DomainControllers.actt'
		Write-Host 'Searching Domain Controllers'
		$AllDomainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
		$colDomainControllers = @()


		ForEach ($attr in $AllDomainControllers) {
			$objDC = [PSCustomObject] @{
				'Forest'   = $attr.Forest
				'Domain'   = $attr.Domain
				'HostName' = $attr.HostName
			}
			$colDomainControllers += $objDC
		}


		Write-ACTTDataLog -Message "`tExporting Domain Controllers - DomainControllers.actt"
		Write-Host 'Exporting Domain Controllers - DomainControllers.actt'
		Write-ActtFile -Data $colDomainControllers -Path $(Join-Path $Path 'DomainControllers.actt') -Delimiter $delim

	} catch {
		$swExceptionLog.WriteLine('Error - Could not list all Domain Controllers')
		$swExceptionLog.WriteLine($Error[0])
	}

}


Function Get-GPOReportall {
	<#
	.SYNOPSIS
		Lisy all Domain GPOs
	.DESCRIPTION
		Exports a list of Domain GPOs".

	.PARAMETER  Server
	Server to query GPOs

	.PARAMETER  Path
	Path of output file

	.INPUTS
	none

	.OUTPUTS
	File: GPOReportAll.html

	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get All Domain Group Policy Objects Settings GPOReportAll.html'

		Get-GPOReport -All -ReportType html -Path $(Join-Path $Path 'GPOReportAll.html') -Server $Server

		Write-ACTTDataLog -Message "`tExporting All Domain GPOs - GPOReportAll.html"
		Write-Host 'Exporting All Domain GPOs - GPOReportAll.html'

	}

	Catch {
		#Some error occurred attempting to List all Domain Security Policies - Numeric. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not extract all Domain GPOs')
		#$swExceptionLog.WriteLine($WMIError[0])
	}
}


Function Get-TimeDate {
	<#
	.SYNOPSIS
		Returns a formatted Date-Time object

	.DESCRIPTION
		This function will return a date-time object formatted.


	.EXAMPLE
		Get-Date


	.OUTPUTS
		Date-Time object

	.NOTES
		TODO:


	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	Get-Date -Format 'MM/dd/yyyy hh:mm:ss.fff tt'
}


Function Write-ActtFile {
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			HelpMessage = 'Data to be written to Actt File')]
		[ValidateNotNullOrEmpty()]
		[System.Object]$Data,
		[Parameter(Position = 1,
			Mandatory = $true,
			HelpMessage = 'Full Path of the Actt FIle')]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Position = 2,
			Mandatory = $false)]
		[string]$Delimiter = '|^|'
	)

	$VerbosePreference = 'Continue'
	Try {
		# Create StreamWriter
		$SW = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)

		# Write Header
		$Header = ''
		$Properties = @()
		$Properties += ($Data[0] | Get-Member | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
		For ($i = 0; $i -lt $Properties.Count; $i++) {
			If ($i -eq ($Properties.Count - 1)) {
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)'
			} Else {
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)' + $Delimiter
			}
		}
		$SW.WriteLine($Header)


		# Parse through dataset and write out to actt log file
		ForEach ($Result in $Data) {
			$Record = ''

			For ($i = 0; $i -lt $Properties.Count; $i++) {
				# Grab Current Property
				$Prop = $Properties[$i]
				#check if working on last property so we do not add the delimiter to the end of the record.
				If ($i -eq ($Properties.Count - 1)) {
					#Check for $null in $Result.Prop -- Still need to check for arrays in properties.
					If ($null -ne $Result.$Prop) {
						$Record += $Result.$Prop
					}
				} Else {
					If ($null -ne $Result.$Prop) {
						$Record += $Result.$Prop.ToString() + $Delimiter
					} Else {
						$Record += $Delimiter
					}
				}
			}
			$SW.WriteLine($Record)
		}
	}

	Catch {
		#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
		$swExceptionLog.WriteLine($Error[0])
	}

	Finally {
		$SW.close()
	}
}


Function Write-ActtFileContent {
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
			Mandatory = $true,
			ValueFromPipelineByPropertyName = $true,
			HelpMessage = 'Data to be written to Actt File')]
		[ValidateNotNullOrEmpty()]
		[System.Object]$Data,
		[Parameter(Position = 1,
			Mandatory = $true,
			HelpMessage = 'Full Path of the Actt FIle')]
		[ValidateNotNullOrEmpty()]
		[string]$Path,
		[Parameter(Position = 2,
			Mandatory = $false)]
		[string]$Delimiter = '|^|'
	)

	$VerbosePreference = 'Continue'
	Try {
		# Create StreamWriter
		$SW = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)

		# Write Header

		$Properties = @()
		$Properties += ($Data[0] | Get-Member | Where-Object { $_.MemberType -eq 'NoteProperty' }).Name
		<#
		$Header = ''
		For ($i = 0; $i -lt $Properties.Count; $i++)
		{
			If ($i -eq ($Properties.Count - 1))
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)'
			}
			Else
			{
				$Header += '[' + $($Properties[$i]) + '] NVARCHAR(MAX)' + $Delimiter
			}
		}
		$SW.WriteLine($Header)#>


		# Parse through dataset and write out to actt log file
		ForEach ($Result in $Data) {
			$Record = ''

			For ($i = 0; $i -lt $Properties.Count; $i++) {
				# Grab Current Property
				$Prop = $Properties[$i]
				#check if working on last property so we do not add the delimiter to the end of the record.
				If ($i -eq ($Properties.Count - 1)) {
					#Check for $null in $Result.Prop -- Still need to check for arrays in properties.
					If ($null -ne $Result.$Prop) {
						$Record += $Result.$Prop
					}
				} Else {
					If ($null -ne $Result.$Prop) {
						$Record += $Result.$Prop.ToString() + $Delimiter
					} Else {
						$Record += $Delimiter
					}
				}
			}
			$SW.WriteLine($Record)
		}
	}

	Catch {
		#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
		$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
		$swExceptionLog.WriteLine($Error[0])
	}

	Finally {
		$SW.close()
	}
}


Function Get-DomainTrustsAll {
	<#
	.SYNOPSIS
		List Domain Trusts and their status - trusts.actt

	.DESCRIPTION
		File: trusts.actt
        NameSpace: '\root\MicrosoftActiveDirectory'
        Query: 'SELECT * FROM Microsoft_DomainTrustStatus'
        Report Fields: 'TrustedDomain', 'TrustDirection', 'TrustType', 'TrustAttributes', 'TrustedDCName', 'TrustStatus', 'TrustIsOK'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		trusts.actt

	.NOTES


	.LINK
		about_functions_advanced

	.LINK
		about_comment_based_help
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	Try {
		Write-ACTTDataLog -Message 'Get Domain Trusts and their status - trusts.actt'

		$colTrusts = @()
		$ADDomainTrusts = Get-ADObject -Server $Server -Filter { ObjectClass -eq 'trustedDomain' } -Properties *

		ForEach ($Trust in $ADDomainTrusts) {
			# WMI Request using the trustmon WMI provider
			$TargetName = $Trust.trustPartner
			$WMIStatus = Get-WmiObject -Namespace root\MicrosoftActiveDirectory -Class Microsoft_DomainTrustStatus -ComputerName $Server -Filter "TrustedDomain='$TargetName'" -ErrorAction SilentlyContinue -ErrorVariable WMIError

			if (-not ($WMIError)) {
				$objStatus = [PSCustomObject] @{
					'TrustedDomain'   = $WMIStatus.TrustedDomain
					'TrustDirection'  = $WMIStatus.TrustDirection
					'TrustType'       = $WMIStatus.TrustType
					'TrustAttributes' = $WMIStatus.TrustAttributes
					'TrustedDCName'   = $WMIStatus.TrustedDCName
					'TrustStatus'     = $WMIStatus.TrustStatus
					'TrustIsOK'       = $WMIStatus.TrustIsOK
				}
				$colTrusts += $objStatus
			}
		}

		Write-ACTTDataLog -Message "`tExporting Domain Trusts and their status - trusts.actt"
		Write-Host 'Exporting Domain Trusts and their status - trusts.actt'
		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List Domain Trusts and their status. Writing error $errorlist
		$swExceptionLog.WriteLine("Error while verifying trust with domain '$targetName': $($_.Exception.Message)")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainTrustsLatest {
	<#
	.SYNOPSIS
		List Domain Trusts and their status - trusts.actt

	.DESCRIPTION
		File: trusts.actt
    NameSpace: '\root\MicrosoftActiveDirectory'
    Query: 'SELECT * FROM Microsoft_DomainTrustStatus'
    Report Fields: 'TrustedDomain', 'TrustDirection', 'TrustType', 'TrustAttributes', 'TrustedDCName', 'TrustStatus', 'TrustIsOK'

	.PARAMETER  Server
	Server to query


	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		trusts.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	Try {
		Write-ACTTDataLog -Message 'Get Domain Trusts and their status - trusts.actt'

		$colTrusts = @()
		$ADDomainTrusts = Get-ADTrust -Server $Server -Filter *

		ForEach ($Trust in $ADDomainTrusts) {
			# WMI Request using the trustmon WMI provider
			#$TargetName = $Trust.trustPartner
			#$WMIStatus = Get-WmiObject -Namespace root\MicrosoftActiveDirectory -Class Microsoft_DomainTrustStatus -ComputerName $Server -Credential $Credential -Filter "TrustedDomain='$TargetName'" -ErrorAction SilentlyContinue -ErrorVariable WMIError

			#if (-not ($WMIError))

			$objStatus = [PSCustomObject] @{
				'TrustedDomain'   = $Trust.Name
				'TrustDirection'  = $Trust.Direction
				'TrustType'       = $Trust.TrustType
				'TrustAttributes' = $Trust.TrustAttributes
				#					'TrustedDCName' = $Trust.TrustedDCName
				#					'TrustStatus' = $Trust.TrustStatus
				#					'TrustIsOK' = $Trust.TrustIsOK
			}
			$colTrusts += $objStatus

		}

		Write-ACTTDataLog -Message "`tExporting Domain Trusts and their status - trusts.actt"
		Write-Host 'Exporting Domain Trusts and their status - trusts.actt'
		Write-ActtFile -Data $colTrusts -Path $(Join-Path $Path 'trusts.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List Domain Trusts and their status. Writing error $errorlist
		$swExceptionLog.WriteLine("Error while verifying trust with domain '$Server': $($_.Exception.Message)")
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Write-ACTTDataLog {
	<#
	.SYNOPSIS
		List Domain Trusts and their status - trusts.actt

	.DESCRIPTION
		File: trusts.actt
    NameSpace: '\root\MicrosoftActiveDirectory'
    Query: 'SELECT * FROM Microsoft_DomainTrustStatus'
    Report Fields: 'TrustedDomain', 'TrustDirection', 'TrustType', 'TrustAttributes', 'TrustedDCName', 'TrustStatus', 'TrustIsOK'

	.PARAMETER  Message
	String to write to log file


	.INPUTS
	None

	.OUTPUTS
		Log file
	#>
	# Uses Global StreamWriter object $swACTTDataLog
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
			Mandatory = $true,
			HelpMessage = 'Data to be written to ACTTDataLog File')]
		[ValidateNotNullOrEmpty()]
		[string]$Message
	)

	# Write log entry to $Path
	$swACTTDataLog.WriteLine($(Get-TimeDate) + ': ' + $Message)
}


Function Write-ACTTConfigSettings {
	<#
	.SYNOPSIS
	Write config setting file

	.DESCRIPTION
	Write setting, value pair to config file

	.PARAMETER  Settings
	Name of setting to be saved


	.PARAMETER  Value
	Value to be saved

	.INPUTS
	None

	.OUTPUTS
		Config file ACTT_CONFIG_SETTINGS.actt
	#>
	# Uses Global StreamWriter object $swACTTDataLog
	[CmdletBinding()]
	Param
	(
		[Parameter(Position = 0,
			Mandatory = $true,
			HelpMessage = 'Setting to be written to ACTT_CONFIG_SETTINGS.actt')]
		[ValidateNotNullOrEmpty()]
		[string]$Setting,
		[Parameter(Position = 1,
			Mandatory = $true,
			HelpMessage = 'Setting Value to be written to ACTT_CONFIG_SETTINGS.actt')]
		[ValidateNotNullOrEmpty()]
		[string]$Value
	)

	# Write log entry to $Path

	$swConfigSettings.WriteLine($Setting + $Delim + $Value)
}


Function Get-ConfigSettings {
	<#
	.SYNOPSIS
	Read config setting file

	.DESCRIPTION
	Read setting, value pair to config file


	.INPUTS
	Config file ACTT_CONFIG_SETTINGS.actt

	.OUTPUTS
	None
	#>
	Try {

		$WMIOSQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_OperatingSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$WMIComputerQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_ComputerSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError

		# This could be just a Hash Table instead...
		If ($null -ne $WMIOSQuery) {
			$User = $env:USERDOMAIN + '\' + $env:USERNAME
			$FQDN = [System.Net.DNS]::GetHostByName('').HostName
			Write-ACTTConfigSettings -Setting 'ProductType' -Value $WMIOSQuery.ProductType
			Write-ACTTConfigSettings -Setting 'Version' -Value $WMIOSQuery.Version
			Write-ACTTConfigSettings -Setting 'ServicePackMajorVersion' -Value $WMIOSQuery.ServicePackMajorVersion
			Write-ACTTConfigSettings -Setting 'ServicePackMinorVersion' -Value $WMIOSQuery.ServicePackMinorVersion
			Write-ACTTConfigSettings -Setting 'Caption' -Value $WMIOSQuery.Caption
			Write-ACTTConfigSettings -Setting 'Fully Qualified Domain Name' -Value $FQDN
			Write-ACTTConfigSettings -Setting 'Domain Name' -Value $WMIComputerQuery.Domain
			Write-ACTTConfigSettings -Setting 'ServerName' -Value $WMIComputerQuery.Name
			Write-ACTTConfigSettings -Setting 'UserName' -Value $User
			Write-ACTTConfigSettings -Setting 'Extract Script Version' -Value $ScriptVersion

		}
	}

	Catch {
		#Some error occurred attempting to Export Environment of the System performing the audit data extraction - ACTT_CONFIG_SETTINGS.actt. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Export Environment of the System performing the audit data extraction')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-HostAndUserDetails {
	<#
	.SYNOPSIS
	Read Host and UserName from file

	.DESCRIPTION
	Read Host and UserName from HostandUserName.actt file

	.INPUTS
	HostandUserName.actt

	.OUTPUTS
	None
	#>
	Try {
		Write-ACTTDataLog -Message 'Get Host and User name currently logged in - HostandUserName.actt'

		$colHostandUserName = @()
		$WMIQuery = Get-WmiObject -Namespace root\cimv2 -Query 'SELECT * FROM Win32_ComputerSystem' -ErrorAction SilentlyContinue -ErrorVariable WMIError

		If ($null -ne $WMIQuery) {
			$objTemp = [PSCustomObject] @{
				'Name'     = $WMIQuery.Name
				'UserName' = $env:USERNAME
			}

			# Add psCustomObject to Collection
			$colHostandUserName += $objTemp
		}

		Write-Host 'Exporting Host and User name currently logged in - HostandUserName.actt'
		Write-ACTTDataLog -Message "`tExporting Host and User name currently logged in - HostandUserName.actt"
		Write-ActtFile -Data $colHostandUserName -Path $(Join-Path $Path 'HostandUserName.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to Get Host and User name currently logged in - HostandUserName.actt. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Get Host and User name currently logged in')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DomainOUsAll {
	<#
	.SYNOPSIS
	Export all domain OUs

	.DESCRIPTION
	Export all domain OUs
	Report Fields: 'Name', 'objectClass', 'Description', 'WhenCreated', 'LinkedGroupPolicyObjects', 'DistinguishedName'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		OU.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all OUs in Domain - OU.actt'

		Write-Host 'Searching All OUs'
		$AllOUs = Get-ADOrganizationalUnit -Server $Server -Filter * -Properties Name, objectClass, Description, WhenCreated, LinkedGroupPolicyObjects, DistinguishedName -ErrorAction Stop

		$colOUs = @()

		foreach ($OU in $AllOUs) {
			#Build ComputerObject
			$objOU = [PSCustomObject] @{
				'Name'                     = $OU.Name
				'objectClass'              = $OU.objectClass
				'Description'              = $OU.Description
				'WhenCreated'              = $OU.WhenCreated
				'LinkedGroupPolicyObjects' = $OU.LinkedGroupPolicyObjects
				'DistinguishedName'        = $OU.DistinguishedName
			}

			# Add objDC to colDCs
			$colOUs += $objOU
		}

		Write-ACTTDataLog -Message "`tExporting OUs - OU.actt"
		Write-Host 'Exporting OUs - OU.actt'
		Write-ActtFile -Data $colOUs -Path $(Join-Path $Path 'OU.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all OUs. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all OUs in domain')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainGroupsAll {
	<#
	.SYNOPSIS
	Export all Domain Groups

	.DESCRIPTION
	Get all domain Groups and export to select file
  Report Fields: 'GroupName', 'GroupSID', 'Description'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
	Groups.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all Domain Groups - groups.actt
	Try {
		Write-ACTTDataLog -Message 'Get all Domain Groups - groups.actt'
		Write-Host 'Searching All Domain Groups'
		$AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID, Description -ErrorAction Stop
		$colGroups = @()

		foreach ($DGroup in $AllDomainGroups) {
			try {
				#Build GroupObject
				$objGroup = [PSCustomObject] @{
					'GroupName'   = $DGroup.SamAccountName
					'GroupSID'    = $DGroup.ObjectSID
					'Description' = $DGroup.Description
				}

				# Add objDC to colDCs
				$colGroups += $objGroup
			} Catch {
				$swExceptionLog.WriteLine($Error[0])
				continue
			}

		}

		Write-ACTTDataLog -Message "`tExporting All Domain Groups - groups.actt"
		Write-Host 'Exporting All Domain Groups - groups.actt'
		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Groups')
		$swExceptionLog.WriteLine($Error[0])
	}
}


#tarun
function Get-DomainGroupsMembersAll {
	<#
	.SYNOPSIS
	Export all Domain Groups members

	.DESCRIPTION
	Get all domain Groups members and export to select file
	Report Fields: GroupName, GroupSID, Member, objectSID

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
	groupmembers.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)
	#List all members in Domain Groups - groupmembers.actt
	Try {
		$Path = Join-Path $Path 'groupmembers.actt'
		Write-ACTTDataLog -Message 'Get all Domain Group Members - groupmembers.actt'
		<#
			File: groupmembers.actt
			Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'
		#>
		Write-Host 'Searching All Domain Group Members'
		$AllDomainGroups = Get-ADGroup -Server $Server -Filter * -Properties SamAccountName, ObjectSID , members -ErrorAction Stop
		$Header = "[GroupName] NVARCHAR(MAX)$Delim[GroupSID] NVARCHAR(MAX)$Delim[Member] NVARCHAR(MAX)$Delim[objectSID] NVARCHAR(MAX)"
		$SW = New-Object System.IO.StreamWriter($Path, $false, [System.Text.Encoding]::Unicode)
		$SW.WriteLine($Header)
		$SW.Close()
		Write-Host 'Found '$AllDomainGroups.count' Groups in the domain. Extracting group members information in the background. Kindly note that the extraction time depends on the size of AD'
		foreach ($DGroup in $AllDomainGroups) {
			Try {
				$GroupMembersObj = @()
				$GroupMembers = Get-ADGroupMember -Identity $DGroup -ErrorAction continue
				$Delimiter = "$Delim"
				$GroupString = $DGroup.SamAccountName + $Delimiter + $DGroup.SID
				if ($null -eq $GroupMembers) {
					$Member = $GroupString + $Delimiter + $Delimiter
					$Member | Out-File -FilePath $Path -Force -Append
					Continue
				}
				foreach ($GroupMember in $GroupMembers) {
					Try {
						$Member = $GroupString + $Delimiter + $GroupMember.Name + $Delimiter + $GroupMember.SID
						$GroupMembersObj += $Member
					} Catch {
						$swExceptionLog.WriteLine('Error - Issue with the Group Member listing')
						$swExceptionLog.WriteLine($GroupMember)
						$swExceptionLog.WriteLine($Error[0])
					}
				}
				$VerbosePreference = 'Continue'
				#region Writeout
				#write content to GroupMembers with SreamWriter
				Try {
					# Create StreamWriter
					$SW = New-Object System.IO.StreamWriter($Path, $true, [System.Text.Encoding]::Unicode)
					# Parse through dataset and write out to actt log file
					Foreach ($Result in $GroupMembersObj) {
						$SW.WriteLine($Result)
					}
				} Catch {
					#Some error occurred attempting to write the extract .actt file. Writing error $errorlist
					$swExceptionLog.WriteLine("Error - Writing Export .actt File $Path")
					$swExceptionLog.WriteLine($Error[0])
				} Finally {
					$SW.close()
				}
				#endregion Writeout
			} Catch {
				#Code to extract Group Information using ADSI-LDAP in case of different domain groups
				$swExceptionLog.WriteLine('Error - Issue with the Group Listing')
				$swExceptionLog.WriteLine($DGroup)
				$swExceptionLog.WriteLine($Error[0])
				$MembersOfDiffDomain = Get-ADGroup -Identity $DGroup -Properties Member | Select-Object -ExpandProperty Member
				Foreach ($Member in $MembersOfDiffDomain) {
					trap [Exception] {
						$swExceptionLog.WriteLine('Error - Trapped Exception for Below Group and Member')
						$swExceptionLog.WriteLine($DGroup)
						$swExceptionLog.WriteLine($Member)
						$swExceptionLog.WriteLine($_.Exception.Message)
						continue
					}
					$Delimiter = "$Delim"
					$ObjectS = [ADSI]"LDAP://$Member"
					$objectSID = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $($ObjectS.objectsid), 0).value
					$MemberString = $DGroup.SamAccountName + $Delimiter + $DGroup.SID + $Delimiter + $ObjectS.sAMAccountName + $Delimiter + $objectSID.ToString()
					$MemberString | Out-File -FilePath $Path -Force -Append
				}
				continue
			}
		}
		Write-ACTTDataLog -Message "`tExporting All Domain Groupmembers - groupmembers.actt"
		Write-Host 'Exporting All Domain Group members - groupmembers.actt'
	} catch {
		#Some error occurred attempting to List all Domain Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Group Members. Function name Get-DomainGroupsMembersAll')
		$swExceptionLog.WriteLine($Error[0])
	}

}


Function Get-DomainSensitiveGroupMembersAll {
	<#
	.SYNOPSIS
	EXport List all members in sensitive Domain Groups

	.DESCRIPTION
	Export all members in sensitive Domain Groups to file
	Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: groupmembers2.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all members in sensitive Domain Groups - groupmembers2.actt
	Try {
		Write-ACTTDataLog -Message 'Get all members in sensitive Domain Groups - groupmembers2.actt'

		Write-Host 'Searching Sensitive Domain Group Members'
		$SensitiveDomainGroupList = 'Domain Admins', 'Group Policy Creator Owners', 'Administrators', 'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Server Operators', 'DnsAdmins'
		$colSensitiveDomainGroups = @()

		Foreach ($Group in $SensitiveDomainGroupList) {
			Try {
				# Get Group object
				$Filter = 'Name -eq ' + '"' + $Group + '"'
				$ADGroup = Get-ADGroup -Server $Server -Filter $Filter
				If ($null -eq $ADGroup -and $Group -eq 'Enterprise Admins' -or $Group -eq 'Schema Admins') {
					Write-ACTTDataLog -Message "`tSkipping Forest Level Sensitive Group - $Group in Child Domain $Server"
				} Else {
					#Get Group Members with Recursion
					$Members = Get-ADGroupMember -Identity $ADGroup -Recursive -ErrorAction Continue

					#Check for Empty $Members, if empty create the $objGroup psCustomObject with empty strings for member and objectSID
					if ($null -eq $Members) {
						$objGroup = [PSCustomObject] @{
							'GroupName' = $ADGroup.Name
							'GroupSID'  = $ADGroup.SID
							'Member'    = ''
							'objectSID' = ''
						}
						$colSensitiveDomainGroups += $objGroup
					} Else {
						#Else create a $objGroup for each member
						foreach ($Member in $Members) {
							Try {
								$objGroup = [PSCustomObject] @{
									'GroupName' = $ADGroup.Name
									'GroupSID'  = $ADGroup.SID
									'Member'    = $Member.Name
									'objectSID' = $Member.SID
								}
								$colSensitiveDomainGroups += $objGroup
							} Catch {
								$swExceptionLog.WriteLine('Error - Issue with member listing')
								$swExceptionLog.WriteLine($Member)
								$swExceptionLog.WriteLine($Error[0])
							}


						}
					}
				}
			} Catch {
				$swExceptionLog.WriteLine('Error - Issue with Group listing')
				$swExceptionLog.WriteLine($Group)
				$swExceptionLog.WriteLine($Error[0])
			}
		}

		Write-ACTTDataLog -Message "`tExporting Sensitive Domain Group Members - groupmembers2.actt"
		Write-Host 'Exporting Sensitive Domain Group Members - groupmembers2.actt'
		Write-ActtFile -Data $colSensitiveDomainGroups -Path $(Join-Path $Path 'groupmembers2.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all sensitive Domain Groups Members with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Senstive Domain Groups Members')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DomainUsersAll {
	<#
	.SYNOPSIS
	EXport all domain Users

	.DESCRIPTION
	Export all domain users to file
	Report	Fields:'SamAccountName', 'DistinguishedName', 'ObjectSID', 'Name', 'Description', 'pwdlastset',
			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'	'CannotChangePassword', 'LockedOut', 'Enabled', 			'PasswordNeverExpires', 'PasswordNotRequired', 'AccountExpirationDate', 'LastLogonDate', 'whenchanged'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: users.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all Domain Users Accounts - users.actt
	Try {
		Write-ACTTDataLog -Message 'Get all Domain Users Accounts - users.actt'
		Write-Host 'Exporting All Domain Users'

		$UserProps = @(
			'SamAccountName', 'DistinguishedName', 'ObjectSID',
			'Name', 'Description', 'pwdlastset',
			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
			'CannotChangePassword', 'LockedOut', 'Enabled',
			'PasswordNeverExpires', 'PasswordNotRequired', 'AccountExpirationDate', 'LastLogonDate', 'whenchanged')

		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
		Write-ACTTDataLog -Message "`tSearch Returned $($AllDomainUsers.Count) Users"
		Write-Host "Search Returned $($AllDomainUsers.Count) Users"
		$colUsers = @()
		$colUsers2 = @()

		foreach ($User in $AllDomainUsers) {
			#Build psCustomObject
			$objUser = [PSCustomObject] @{
				'ObjectSID'             = $User.ObjectSID
				'SamAccountName'        = $User.SamAccountName
				'Name'                  = $User.Name
				'Description'           = $User.Description
				'Enabled'               = $User.Enabled
				'pwdlastset'            = $User.pwdlastset
				'useraccountcontrol'    = $User.useraccountcontrol
				'whencreated'           = $User.whencreated
				'Lockedout'             = $User.LockedOut
				'PasswordNeverExpires'  = $User.PasswordNeverExpires
				'PasswordNotRequired'   = $User.PasswordNotRequired
				'CannotChangePassword'  = $User.CannotChangePassword
				'lastlogontimestamp'    = $User.lastlogontimestamp
				'LastLogonDate'         = $User.LastLogonDate
				'AccountExpirationDate' = $User.AccountExpirationDate
				'DistinguishedName'     = $User.DistinguishedName
				'whenchanged'           = $User.whenchanged
			}

			$objUser2 = [PSCustomObject] @{
				'SID'                = $User.ObjectSID
				'FullName'           = $User.Name
				'Name'               = $User.SamAccountName
				'Description'        = $User.Description
				'Disabled'           = -not $User.Enabled
				'Lockout'            = $User.LockedOut
				'PasswordExpires'    = -not $User.PasswordNeverExpires
				'PasswordRequired'   = -not $User.PasswordNotRequired
				'PasswordChangeable' = -not $User.CannotChangePassword
				'DistinguishedName'  = $User.DistinguishedName
			}

			# Add psCustomObject to Collection
			$colUsers += $objUser
			$colUsers2 += $objUser2
		}

		Write-Host 'Exporting All Domain Users - users.actt'
		Write-ACTTDataLog -Message "`tExporting All Domain Users - users.actt"
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt') -Delimiter $delim

		Write-Host 'Exporting All Domain Users - users2.actt'
		Write-ACTTDataLog -Message "`tExporting All Domain Users - users2.actt"
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainUsersStatus {
	<#
	.SYNOPSIS
	EXport all Domain Users Accounts

	.DESCRIPTION
	Export all domain users to file
	Report	Fields:	'SamAccountName', 'DistinguishedName', 'ObjectSID',	'Name', 'Description', 'pwdlastset', 			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'	'CannotChangePassword', 'LockedOut', 'Enabled',			'PasswordNeverExpires', 'PasswordNotRequired'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: users2.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)
	Try {
		Write-ACTTDataLog -Message 'Get all Domain Users Accounts - users2.actt'
		Write-Host 'List All Domain Users2'

		$UserProps = @(
			'SamAccountName', 'DistinguishedName', 'ObjectSID',
			'Name', 'Description', 'pwdlastset',
			'useraccountcontrol', 'whencreated', 'lastlogontimestamp'
			'CannotChangePassword', 'LockedOut', 'Enabled',
			'PasswordNeverExpires', 'PasswordNotRequired')

		$AllDomainUsers = Get-ADUser -Server $Server -Filter * -Properties $UserProps
		Write-ACTTDataLog -Message "`tSearch Returned $($AllDomainUsers.Count) Users2"
		Write-Host "Search Returned $($AllDomainUsers.Count) Users2"

		$colUsers2 = @()

		foreach ($User in $AllDomainUsers) {
			#Build psCustomObject

			$objUser2 = [PSCustomObject] @{
				'SID'                = $User.ObjectSID
				'FullName'           = $User.Name
				'Name'               = $User.SamAccountName
				'Description'        = $User.Description
				'Disabled'           = -not $User.Enabled
				'Lockout'            = $User.LockedOut
				'PasswordExpires'    = -not $User.PasswordNeverExpires
				'PasswordRequired'   = -not $User.PasswordNotRequired
				'PasswordChangeable' = -not $User.CannotChangePassword
				'DistinguishedName'  = $User.DistinguishedName
			}

			# Add psCustomObject to Collection

			$colUsers2 += $objUser2
		}


		Write-Host 'Exporting All Domain Users - users2.actt'
		Write-ACTTDataLog -Message "`tExporting All Domain Users - users2.actt"
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users2.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users2')
		$swExceptionLog.WriteLine($Error[0])
	}
}

Function Get-DirectoryUsersAll {
	<#
	.SYNOPSIS
	EXport  all Domain Users Accounts via DirectorySearcher

	.DESCRIPTION
	Export all domain users to file
	Report	Fields:	'SamAccountName', 'DistinguishedName', 'ObjectSID', 'Name', 'Description', 'pwdlastset', 'useraccountcontrol', 'whencreated', 'lastlogontimestamp', 'whenchanged', 'accountexpires'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: users.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	Try {
		Write-ACTTDataLog -Message 'Get all Domain Users Accounts - users.actt via DirectorySearcher'
		Write-Host 'List all Domain Users Accounts- users.actt'

		$root = [ADSI]''
		$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

		$searcher.filter = '(&(objectCategory=person)(objectClass=user))'

		$searcher.PropertiesToLoad.AddRange(@('SamAccountName', 'DistinguishedName', 'ObjectSID', 'Name', 'Description', 'pwdlastset', 'useraccountcontrol', 'whencreated', 'lastlogontimestamp', 'whenchanged', 'accountexpires'))
		$searcher.PageSize = 1000
		$USERLIST = $searcher.FindAll()

		Write-ACTTDataLog -Message "`tSearch Returned $($USERLIST.Count) Users"
		Write-Host "Search Returned $($USERLIST.Count) Users"
		$colUsers = @()

		foreach ($User in $USERLIST) {
			#Build psCustomObject
			$objUser = [PSCustomObject] @{
				'ObjectSID'             = New-Object System.Security.Principal.SecurityIdentifier($User.properties.objectsid[0], 0)
				'SamAccountName'        = [string]$User.properties['samaccountname']
				'Name'                  = [string]$User.properties['name']
				'Description'           = [string]$User.properties['description']
				'pwdlastset'            = [string]$User.properties['pwdlastset']
				'useraccountcontrol'    = [string]$User.properties['useraccountcontrol']
				'whencreated'           = [string]$User.properties['whencreated']
				'lastlogontimestamp'    = [string]$User.properties['lastlogontimestamp']
				#'LastLogonDate' = [string]$User.properties.lastlogonDate
				'DistinguishedName'     = [string]$User.properties['distinguishedname']
				'whenchanged'           = [string]$User.properties['whenchanged']
				'AccountExpirationDate' = If (($User.Properties['accountexpires'] -le 0) -or ($User.Properties['accountexpires'] -gt 2650385917000000000)) {
					''
    } Else {
					[datetime]::fromfiletime([string]$User.Properties['accountexpires'])
    }

			}
			# Add psCustomObject to Collection
			$colUsers += $objUser

		}

		Write-Host 'Exporting All Domain Users - users.actt'
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt') -Delimiter $delim
		Write-ACTTDataLog -Message "`tExporting All Domain Users - users.actt"

	}

	Catch {
		#Some error occurred attempting to List all Domain Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Users')
		$swExceptionLog.WriteLine($Error[0])
	}

}


Function Get-DefDomainPwdPol {
	<#
	.SYNOPSIS
	Export Default Domain Password Policy

	.DESCRIPTION
	Export Default Domain Password Policy parameters to file
	Report	Fields:	'ComplexityEnabled', 'LockoutDuration', 'lockOutObservationWindow', 'lockoutThreshold', 'MaxPasswordAge', 'MinPasswordAge', 'MinPasswordLength', 'PasswordHistoryCount', 'ReversibleEncryptionEnabled'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: SecPol.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	Try {
		Write-ACTTDataLog -Message 'Get Default Domain Password Policies - SecPol.actt'
		$RootDSE = Get-ADRootDSE -Server $Server
		$AccountPolicy = Get-ADDefaultDomainPasswordPolicy -Server $Server -Identity $RootDSE.defaultNamingContext
		$colDefDomainPolicy = @()
		$PolicyNeeded = @('ComplexityEnabled', 'LockoutDuration', 'lockOutObservationWindow', 'lockoutThreshold', 'MaxPasswordAge', 'MinPasswordAge', 'MinPasswordLength', 'PasswordHistoryCount', 'ReversibleEncryptionEnabled')
		If ($null -ne $AccountPolicy) {
			ForEach ($Policy in $PolicyNeeded) {

				#Build DomainControllerObject
				$objSP = [PSCustomObject] @{
					'SettingName'  = $Policy
					'SettingValue' = $AccountPolicy.$Policy
				}
				$colDefDomainPolicy += $objSP


			}
		} else {
			ForEach ($item in $PolicyNeeded) {
				$objSP = [PSCustomObject] @{
					'SettingName'  = $item
					'SettingValue' = 'Not Defined'
				}
				# Add objSP to colSPNumeric
				$colDefDomainPolicy += $objSP
			}
		}

		Write-ACTTDataLog -Message "`tExporting Default Domain Password Policies - SecPol.actt"
		Write-Host 'Exporting Default Domain Password Policies - SecPol.actt'
		Write-ActtFile -Data $colDefDomainPolicy -Path $(Join-Path $Path 'SecPol.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Default Domain Password Policies - SecPol.actt')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-FineGrainedPSO {
	<#
	.SYNOPSIS
	Export all Domain PSOs Accounts via DirectorySearcher

	.DESCRIPTION
	Export all Domain PSOs Accounts via DirectorySearcher
	Report	Fields:	'msds-lockoutduration', 'msds-minimumpasswordage', 'msds-lockoutobservationwindow', 'msds-maximumpasswordage', 'msds-lockoutthreshold', 'msds-passwordcomplexityenabled', 'msds-passwordhistorylength', 'msds-minimumpasswordlength', 'msds-psoappliesto', 'whenchanged', 'msds-passwordsettingsprecedence', 'cn'

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: PSOs.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all Domain PSOs Accounts - PSOs.actt
	Try {
		Write-ACTTDataLog -Message 'Get all Domain PSOs Accounts - PSOs.actt via DirectorySearcher'
		Write-Host 'List all Domain PSOs Accounts- PSOs.actt'

		$root = [ADSI]''
		$searcher = New-Object System.DirectoryServices.DirectorySearcher($root)

		$searcher.filter = '(objectClass=msDS-PasswordSettings)'

		$searcher.PropertiesToLoad.AddRange(@('msds-lockoutduration', 'msds-minimumpasswordage', 'msds-lockoutobservationwindow', 'msds-maximumpasswordage', 'msds-lockoutthreshold', 'msds-passwordcomplexityenabled', 'msds-passwordhistorylength', 'msds-minimumpasswordlength', 'msds-psoappliesto', 'whenchanged', 'msds-passwordsettingsprecedence', 'cn'))
		$searcher.PageSize = 1000
		$PSOLIST = $searcher.FindAll()

		Write-ACTTDataLog -Message "`tSearch Returned $($PSOLIST.Count) PSOs"
		Write-Host "Search Returned $($PSOLIST.Count) PSOs"
		$colPSOs = @()

		foreach ($PSO in $PSOLIST) {
			#Caculation of timespan
			$MaxPwdAge = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-maximumpasswordage')"
			$ObservationWindow = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutobservationwindow')"
			$MinPwdAge = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-minimumpasswordage')"
			$LockOutDuration = New-Object -TypeName TimeSpan -ArgumentList "$($PSO.properties.'msds-lockoutduration')"
			#Build psCustomObject
			foreach ($dnApp in $PSO.properties.'msds-psoappliesto') {
				$ADObject = [ADSI]"LDAP://$dnApp"

				$objUser = [PSCustomObject] @{
					'PSOName'                         = "$($PSO.properties.'cn')"
					'AppliesTo'                       = "$($ADObject.Get('cn'))"
					'ObjectType'                      = "$($ADObject.Get('objectclass'))"
					'msds-maximumpasswordage'         = if ($MaxPwdAge -eq '-10675199.02:48:05.4775808') {
						'Never'
     } else {
						$MaxPwdAge
     }
					'msds-passwordsettingsprecedence' = $($PSO.properties.'msds-passwordsettingsprecedence')
					'msds-lockoutthreshold'           = $($PSO.properties.'msds-lockoutthreshold')
					'msds-passwordcomplexityenabled'  = $($PSO.properties.'msds-passwordcomplexityenabled')
					'msds-passwordhistorylength'      = $($PSO.properties.'msds-passwordhistorylength')
					'msds-lockoutobservationwindow'   = if ($ObservationWindow -eq '-10675199.02:48:05.4775808') {
						'Never'
     } else {
						$ObservationWindow
     }
					#'msds-passwordreversibleencryptionenabled' = $($PSO.properties.'msds-passwordreversibleencryptionenabled')
					'msds-minimumpasswordage'         = if ($MinPwdAge -eq '-10675199.02:48:05.4775808') {
						'Never'
     } else {
						$MinPwdAge
     }
					'msds-lockoutduration'            = if ($LockOutDuration -eq '-10675199.02:48:05.4775808') {
						'Never'
     } else {
						$LockOutDuration
     }
					'msds-minimumpasswordlength'      = $($PSO.properties.'msds-minimumpasswordlength')
					'whenchanged'                     = $($PSO.properties.whenchanged)
				}
				# Add psCustomObject to Collection
				$colPSOs += $objUser

			}



		}

		Write-Host 'Exporting All Domain PSOs - PSOs.actt'
		Write-ActtFile -Data $colPSOs -Path $(Join-Path $Path 'PSOs.actt') -Delimiter $delim
		Write-ACTTDataLog -Message "`tExporting All Domain PSOs - PSOs.actt"

	}

	Catch {
		#Some error occurred attempting to List all Domain PSOs Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain PSOs')
		$swExceptionLog.WriteLine($Error[0])
	}

}


Function Get-DomainPwdPol {
	<#
	.SYNOPSIS
	Export Domain Password Policies

	.DESCRIPTION
	Export Domain Password Policies to file
	Report	Fields:	Parameter, Value

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: domainpolicy.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get Domain pwdPolicies - domainpolicy.actt'
		$RootDSE = Get-ADRootDSE -Server $Server
		$AccountPolicy = Get-ADObject -Identity $RootDSE.defaultNamingContext -Server $Server -Property *
		$colDomainPolicy = @()

		If ($AccountPolicy.pwdProperties -band 0x4) {
			#Writing to Data Log
			Write-ACTTDataLog -Message "`tPrevent Transfer of Passwords in Clear Text: Enabled"
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Prevent Transfer of Passwords in Clear Text'
				'Value'     = 'Enabled'
			}
			$colDomainPolicy += $objDomainPolicy
		} Else {
			#'Writing to Data Log
			Write-ACTTDataLog -Message "`tPrevent Transfer of Passwords in Clear Text: Disabled"
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Prevent Transfer of Passwords in Clear Text'
				'Value'     = 'Disabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}

		If ($AccountPolicy.pwdProperties -band 0x8) {
			#Writing to Data Log
			Write-ACTTDataLog -Message "`tAllow Lockout of Administrator Account: Enabled"
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Allow Lockout of Administrator Account'
				'Value'     = 'Enabled'
			}
			$colDomainPolicy += $objDomainPolicy
		} Else {
			#Writing to Data Log
			Write-ACTTDataLog -Message "`tAllow Lockout of Administrator Account: Disabled"
			$objDomainPolicy = [PSCustomObject] @{
				'Parameter' = 'Allow Lockout of Administrator Account'
				'Value'     = 'Disabled'
			}
			$colDomainPolicy += $objDomainPolicy
		}

		Write-ACTTDataLog -Message "`tExporting Domain pwdPolicies - domainpolicy.actt"
		Write-Host 'Exporting Domain pwdPolicies - domainpolicy.actt'
		Write-ActtFile -Data $colDomainPolicy -Path $(Join-Path $Path 'domainpolicy.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Policies')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-DomainSecPol {
	<#
	.SYNOPSIS
	Export Domain Security Policies - Numeric

	.DESCRIPTION
	Export Get Domain Security Policies to file
	Report	Fields:	KeyName, Precedence,Setting

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: Get Domain Security Policies - Numeric - securitypolicynumeric.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)
	Try {
		Write-ACTTDataLog -Message 'Get Domain Security Policies - Numeric - securitypolicynumeric.actt'
		$objWMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT KeyName, Precedence, Setting FROM RSOP_SecuritySettingNumeric' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$colSPNumeric = @()
		$securitypolicynumeric = @('MaximumPasswordAge', 'LockoutBadCount', 'MinimumPasswordLength', 'ResetLockoutCount', 'LockoutDuration', 'PasswordHistorySize', 'MinimumPasswordAge')
		$notDefinedvalue = $null
		If ($null -ne $objWMIQuery) {
			foreach ($Policy in $securitypolicynumeric) {
				$notDefinedvalue = $Policy
				ForEach ($item in $objWMIQuery) {
					If ($Policy -eq $item.KeyName) {
						#Build DomainControllerObject
						$objSP = [PSCustomObject] @{
							'KeyName'    = $item.KeyName
							'Precedence' = $item.Precedence
							'Setting'    = $item.Setting
						}
						$colSPNumeric += $objSP

						$notDefinedvalue = $null

					}


				}

				if ($null -ne $notDefinedvalue) {
					$objSP = [PSCustomObject] @{
						'KeyName'    = $notDefinedvalue
						'Precedence' = 'Not Defined'
						'Setting'    = 'Not Defined'
					}
					# Add objSP to colSPNumeric
					$colSPNumeric += $objSP
				}

			}

		}

		else {
			ForEach ($Policy in $securitypolicynumeric) {
				$objSP = [PSCustomObject] @{
					'KeyName'    = $Policy
					'Precedence' = 'Not Defined'
					'Setting'    = 'Not Defined'
				}
				# Add objSP to colSPNumeric
				$colSPNumeric += $objSP
			}
		}

		Write-ACTTDataLog -Message "`tExporting Domain Security Policies - Numeric - securitypolicynumeric.actt"
		Write-Host 'Exporting Domain Security Policies - Numeric - securitypolicynumeric.actt'
		Write-ActtFile -Data $colSPNumeric -Path $(Join-Path $Path 'securitypolicynumeric.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Security Policies - Numeric. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Security Policies - Numeric')
		$swExceptionLog.WriteLine($WMIError[0])
	}
}

Function Get-DomainSecPolBoolean {
	<#
	.SYNOPSIS
	Export Domain Security Policies - Boolean

	.DESCRIPTION
	Export Domain Security Policies - Boolean - securitypolicyboolean.actt' to file
	Report	Fields:	KeyName, Precedence,Setting


	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: securitypolicyboolean.actt'
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get Domain Security Policies - Boolean - securitypolicyboolean.actt'

		$objWMIQuery = Get-WmiObject -Namespace root\rsop\computer -Query 'SELECT KeyName, Precedence, Setting FROM RSOP_SecuritySettingBoolean' -ComputerName $Server -ErrorAction SilentlyContinue -ErrorVariable WMIError
		$colSPBoolean = @()
		$securityBoolList = @('ClearTextPassword', 'ForceLogoffWhenHourExpire', 'PasswordComplexity', 'RequireLogonToChangePassword')
		$notDefinedvalue = $null
		If ($null -ne $objWMIQuery) {
			foreach ($Policy in $securityBoolList) {
				$notDefinedvalue = $Policy
				ForEach ($item in $objWMIQuery) {
					If ($Policy -eq $item.KeyName) {

						$objSP = [PSCustomObject] @{
							'KeyName'    = $item.KeyName
							'Precedence' = $item.Precedence
							'Setting'    = $item.Setting
						}
						$colSPBoolean += $objSP

						$notDefinedvalue = $null

					}


				}

				if ($null -ne $notDefinedvalue) {
					$objSP = [PSCustomObject] @{
						'KeyName'    = $notDefinedvalue
						'Precedence' = 'Not Defined'
						'Setting'    = 'Not Defined'
					}
					# Add objSP to colSPNumeric
					$colSPBoolean += $objSP
				}

			}

		} else {
			ForEach ($Policy in $securityBoolList) {
				$objSP = [PSCustomObject] @{
					'KeyName'    = $Policy
					'Precedence' = 'Not Defined'
					'Setting'    = 'Not Defined'
				}
				# Add objSP to colSPBoolean
				$colSPBoolean += $objSP
			}
		}

		Write-ACTTDataLog -Message "`tExporting Domain Security Policies - Boolean - securitypolicyboolean.actt"
		Write-Host 'Exporting Domain Security Policies - Boolean - securitypolicyboolean.actt'
		Write-ActtFile -Data $colSPBoolean -Path $(Join-Path $Path 'securitypolicyboolean.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Domain Security Policies - Boolean. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Domain Security Policies - Boolean')
		$swExceptionLog.WriteLine($Error[0])
	}
}


#region LocalServerFunctions
Function Get-LocalGroupsAll {
	<#
	.SYNOPSIS
	Export all Local Groups

	.DESCRIPTION
	Export all Local Groups
  Report Fields: 'GroupName', 'GroupSID', 'Description'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
	File: groups.actt
	#>

	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all Local Groups - groups.actt'

		Write-Host 'Searching All Local Groups'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colGroups = @()

		foreach ($GroupEntry in $AllDEntry.Children | Where-Object { $_.SchemaClassName -eq 'group' }) {
			foreach ($Group in $GroupEntry[0] | Select-Object *) {
				try {
					$objUser = [PSCustomObject] @{
						'objectsid'   = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).Value
						'GroupName'   = $Group.Name
						'Description'	= $Group.Description

					}
				} catch {
					$swExceptionLog.WriteLine($Error[0])
					continue
				}

			}
			$colGroups += $objUser
		}

		Write-ACTTDataLog -Message "`tExporting All Local Groups - groups.actt"
		Write-Host 'Exporting All Local Groups - groups.actt'
		Write-ActtFile -Data $colGroups -Path $(Join-Path $Path 'groups.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Local Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Groups')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-LocalGroupsMembersAll {
	<#
	.SYNOPSIS
	Export all Local Group Members

	.DESCRIPTION
	Export all Local Group Members to file
	Report Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: groupmembers.actt'
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)

	#List all members in Local Groups - groupmembers.actt
	Try {
		Write-ACTTDataLog -Message 'Get all Local Group Members - groupmembers.actt'
		Write-Host 'Searching All Local Group Members'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colLocalGroupsMembers = @()
		#Check for Empty $Members, if empty create the $objGroup psCustomObject
		foreach ($Group in $AllDEntry.Children | Where-Object { $_.SchemaClassName -eq 'group' }) {
			Foreach ($groupdetail in $Group[0] | Select-Object *) {
				try {
					$objGroup = [PSCustomObject] @{
						'GroupName' = $groupdetail.Name
						'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($groupdetail.objectSid.value, 0)).Value
						'Member'    = ''
						'objectSid' = ''

					}
					$colLocalGroupsMembers += $objGroup

				} Catch {
					$swExceptionLog.WriteLine($Error[0])
					continue
				}


			}

			Foreach ($Groupmember in $AllDEntry.psbase.children.find($Group.Name, 'Group')) {
				Try {
					Foreach ($Member in $Groupmember.psbase.invoke('members')) {
						#$MemberDetails = new DirectoryEntry($Member)
						try {
							$objGroup = [PSCustomObject] @{
								'GroupName' = $Group.Name
								'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).Value
								'Member'    = $Member.GetType().InvokeMember('Name', 'GetProperty', $null, $Member, $null)
								'objectSid' = (New-Object System.Security.Principal.SecurityIdentifier($Member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $Member, $null), 0)).Value

							}
							$colLocalGroupsMembers += $objGroup
						} catch {
							$swExceptionLog.WriteLine($Error[0])
							continue
						}
					}
				} Catch {
					$swExceptionLog.WriteLine('Error - With the below GroupMember')
					$swExceptionLog.WriteLine($Member)
					$swExceptionLog.WriteLine($Error[0])
					continue
				}


			}

		}

		Write-ACTTDataLog -Message "`tExporting All Local Groupmembers - groupmembers.actt"
		Write-Host 'Exporting All Local Group members - groupmembers.actt'
		Write-ActtFile -Data $colLocalGroupsMembers -Path $(Join-Path $Path 'groupmembers.actt') -Delimiter $delim
	}

	Catch {
		#Some error occurred attempting to List all Local Groups with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all local Group Members')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Convert-UserFlag {
	<#
	.SYNOPSIS
	Convert User flag to text

	.DESCRIPTION
	Convert User flag to text

	.PARAMETER  UserFlag
	Flag value to convert to string

	.INPUTS
	None

	.OUTPUTS
	None
	#>
	Param ($UserFlag)
	$List = New-Object System.Collections.ArrayList
	Switch ($UserFlag) {

		($UserFlag -BOR 0x0001) {
			[void]$List.Add('SCRIPT')
  }

		($UserFlag -BOR 0x0002) {
			[void]$List.Add('ACCOUNTDISABLE')
  }

		($UserFlag -BOR 0x0008) {
			[void]$List.Add('HOMEDIR_REQUIRED')
  }

		($UserFlag -BOR 0x0010) {
			[void]$List.Add('LOCKOUT')
  }

		($UserFlag -BOR 0x0020) {
			[void]$List.Add('PASSWD_NOTREQD')
  }

		($UserFlag -BOR 0x0040) {
			[void]$List.Add('PASSWD_CANT_CHANGE')
  }

		($UserFlag -BOR 0x0080) {
			[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')
  }

		($UserFlag -BOR 0x0100) {
			[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')
  }

		($UserFlag -BOR 0x0200) {
			[void]$List.Add('NORMAL_ACCOUNT')
  }

		($UserFlag -BOR 0x0800) {
			[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')
  }

		($UserFlag -BOR 0x1000) {
			[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')
  }

		($UserFlag -BOR 0x2000) {
			[void]$List.Add('SERVER_TRUST_ACCOUNT')
  }

		($UserFlag -BOR 0x10000) {
			[void]$List.Add('DONT_EXPIRE_PASSWORD')
  }

		($UserFlag -BOR 0x20000) {
			[void]$List.Add('MNS_LOGON_ACCOUNT')
  }

		($UserFlag -BOR 0x40000) {
			[void]$List.Add('SMARTCARD_REQUIRED')
  }

		($UserFlag -BOR 0x80000) {
			[void]$List.Add('TRUSTED_FOR_DELEGATION')
  }

		($UserFlag -BOR 0x100000) {
			[void]$List.Add('NOT_DELEGATED')
  }

		($UserFlag -BOR 0x200000) {
			[void]$List.Add('USE_DES_KEY_ONLY')
  }

		($UserFlag -BOR 0x400000) {
			[void]$List.Add('DONT_REQ_PREAUTH')
  }

		($UserFlag -BOR 0x800000) {
			[void]$List.Add('PASSWORD_EXPIRED')
  }

		($UserFlag -BOR 0x1000000) {
			[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')
  }

		($UserFlag -BOR 0x04000000) {
			[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')
  }

	}

	$List -join ', '

}


Function Get-LocalUsersAll {
	<#
	.SYNOPSIS
	Export all Local Users Accounts

	.DESCRIPTION
	Export all Local Users Accounts to file
	Report	Fields: AccountExpirationDate, Description, DistinguishedName, lastlogontimestamp, Name, ObjectSID, pwdlastset, SamAccountName, useraccountcontrol, whenchanged, whencreated

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: users.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all Local Users Accounts - users.actt'
		Write-Host 'List All Local Users'


		#$UserProps = @('objectsid', 'lastlogin', 'name', 'description', 'passwordage', 'useraccountcontrol', 'whencreated', 'lastlogontimestamp')

		$AllDEntry = [ADSI]"WinNT://$Server"

		#Write-ACTTDataLog -Message "`tSearch Returned $($AllDEntry.Count) Users"
		#Write-Host "Search Returned $($AllDEntry.Count) Users"
		$colUsers = @()
		$colUsers2 = @()

		foreach ($UserEntry in $AllDEntry.Children | Where-Object { $_.SchemaClassName -eq 'user' }) {
			try {
				foreach ($User in $UserEntry[0] | Select-Object *) {
					try {
						$objUser = [PSCustomObject] @{
							'objectsid'            = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
							'Name'                 = $User.Name
							'FullName'             = $User.FullName
							#						'Username'		     = $User.Username
							'Description'          = $User.Description
							'lastlogin'            = If ($User.LastLogin[0] -is [datetime]) {
								$User.LastLogin[0]
							} Else {
								'Never logged  on'
							}
							'passwordage'          = [math]::Round($User.PasswordAge[0] / 86400)
							'useraccountcontrol'   = $User.userflags
							'ACCOUNTDISABLE'       = Switch ($User.userflags[0]) {
 ($User.userflags[0] -BOR 0x0002) {
									'True'
								}
								default {
									'False'
								}
							}
							'PASSWD_CANT_CHANGE'   = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0040) {
									'True'
								}
								default {
									'False'
								}
							}
							'LOCKOUT'              = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0010) {
									'True'
								}
								default {
									'False'
								}
							}
							'PASSWD_NOTREQD'       = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'True'
								}
								default {
									'False'
								}
							}
							'DONT_EXPIRE_PASSWORD' = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'True'
								}
								default {
									'False'
								}
							}
							'PasswordExpired'      = $User.PasswordExpired

						}
						$colUsers += $objUser


					} catch {
						$swExceptionLog.WriteLine('Error - Issue identified for one of the Local Users')
						$swExceptionLog.WriteLine($User)
						$objUser = [PSCustomObject] @{
							'objectsid'            = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
							'Name'                 = $User.Name
							'FullName'             = $User.FullName
							#						'Username'		     = $User.Username
							'Description'          = $User.Description
							'lastlogin'            = ''
							'passwordage'          = [math]::Round($User.PasswordAge[0] / 86400)
							'useraccountcontrol'   = $User.userflags
							'ACCOUNTDISABLE'       = Switch ($User.userflags[0]) {
 ($User.userflags[0] -BOR 0x0002) {
									'True'
								}
								default {
									'False'
								}
							}
							'PASSWD_CANT_CHANGE'   = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0040) {
									'True'
								}
								default {
									'False'
								}
							}
							'LOCKOUT'              = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0010) {
									'True'
								}
								default {
									'False'
								}
							}
							'PASSWD_NOTREQD'       = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'True'
								}
								default {
									'False'
								}
							}
							'DONT_EXPIRE_PASSWORD' = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'True'
								}
								default {
									'False'
								}
							}
							'PasswordExpired'      = $User.PasswordExpired

						}
						$colUsers += $objUser
						$swExceptionLog.WriteLine($Error[0])
						continue
					}

				}
			} Catch {
				$swExceptionLog.WriteLine('Error - Issue identified for one of the Local UserEntry Object')
				$swExceptionLog.WriteLine($UserEntry)
				$swExceptionLog.WriteLine($Error[0])
				continue
			}


		}

		foreach ($UserEntry in $AllDEntry.Children | Where-Object { $_.SchemaClassName -eq 'user' }) {
			Try {
				foreach ($User in $UserEntry[0] | Select-Object *) {
					try {
						$objUser2 = [PSCustomObject] @{
							'SID'                = (New-Object System.Security.Principal.SecurityIdentifier($User.objectSid.value, 0)).Value
							'Name'               = $User.Name
							'FullName'           = $User.FullName
							'Description'        = $User.Description
							'useraccountcontrol' = $User.userflags
							'Disabled'           = Switch ($User.userflags[0]) {
 ($User.userflags[0] -BOR 0x0002) {
									'True'
								}
								default {
									'False'
								}
							}
							'PasswordChangeable' = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0040) {
									'False'
								}
								default {
									'True'
								}
							}
							'LOCKOUT'            = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0010) {
									'True'
								}
								default {
									'False'
								}
							}
							'PasswordRequired'   = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'False'
								}
								default {
									'True'
								}
							}
							'PasswordExpires'    = Switch ($User.userflags[0]) {
							($User.userflags[0] -BOR 0x0020) {
									'False'
								}
								default {
									'True'
								}
							}


						}

						$colUsers2 += $objUser2

					} catch {
						$swExceptionLog.WriteLine('Error - Issue identified for one of the Local Users in USERS3')
						$swExceptionLog.WriteLine($User)
						$swExceptionLog.WriteLine($Error[0])
					}

				}
			} Catch {
				$swExceptionLog.WriteLine('Error - Issue identified for one of the Local UserEntry Object in Users3')
				$swExceptionLog.WriteLine($UserEntry)
				$swExceptionLog.WriteLine($Error[0])
				continue
			}


		}


		Write-ACTTDataLog -Message "`tExporting All Local Users - users.actt"
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users.actt') -Delimiter $delim
		Write-Host 'Exporting All Local Users - users.actt'

		Write-ACTTDataLog -Message "`tExporting All Local Users - users3.actt"
		Write-ActtFile -Data $colUsers2 -Path $(Join-Path $Path 'users3.actt') -Delimiter $delim
		Write-Host 'Exporting All Local Users - users3.actt'
	}

	Catch {
		#Some error occurred attempting to List all Local Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Users')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-LocalWMIUsersAll {
	<#
	.SYNOPSIS
	Export all Local Users Accounts

	.DESCRIPTION
	Export all Local Users Accounts to file
	Report	Fields:
					'SID', 'Name', 'FullName', 'Description', 'Disabled', 'useraccountcontrol', 'whencreated', 'Lockout', 'PasswordExpires', 'PasswordRequired', 'PasswordChangeable', 'lastlogontimestamp'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: #List all Local Users Accounts - users.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $false)]
		[String]$Server,
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-ACTTDataLog -Message 'Get all Local Users Accounts - users.actt'
		Write-Host 'Exporting All Local Users'
		$AllLocalUsers = Get-WmiObject -Class Win32_UserAccount -Namespace 'root\cimv2' -Filter "LocalAccount='$True'" -ComputerName $Server -ErrorAction Stop
		Write-ACTTDataLog -Message "`tSearch Returned $($AllLocalUsers.Count) Users"
		Write-Host "Search Returned $($AllLocalUsers.Count) Users"
		$colUsers = @()

		foreach ($User in $AllLocalUsers) {
			try {
				#Build psCustomObject
				$objUser = [PSCustomObject] @{
					'SID'                = $User.SID
					'Name'               = $User.Name
					'FullName'           = $User.FullName
					'Description'        = $User.Description
					'Disabled'           = $User.Disabled
					#'useraccountcontrol'   = $User.useraccountcontrol
					#'whencreated'		   = $User.whencreated
					'Lockout'            = $User.LockOut
					'PasswordExpires'    = $User.PasswordExpires
					'PasswordRequired'   = $User.PasswordRequired
					'PasswordChangeable' = $User.PasswordChangeable
					#'lastlogontimestamp'   = $User.LastLogin
				}
				# Add psCustomObject to Collection
				$colUsers += $objUser
			} Catch {
				$swExceptionLog.WriteLine('Error - Could not list this Local Users2')
				$swExceptionLog.WriteLine($Error[0])
				continue
			}
		}
		Write-ACTTDataLog -Message "`tExporting All Local Users - users2.actt"
		Write-ActtFile -Data $colUsers -Path $(Join-Path $Path 'users2.actt') -Delimiter $delim
		Write-Host 'Exporting All Local Users - users2.actt'
	} Catch {
		#Some error occurred attempting to List all Local Users Accounts with requested attributes. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not list all Local Users2')
		$swExceptionLog.WriteLine($Error[0])
	}
}


Function Get-LocalPwdPol {
	<#
	.SYNOPSIS
	Export Local pwdPolicies

	.DESCRIPTION
	Export Local pwdPolicies  to file
	Report	Fields: 'MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'ClearTextPassword'


	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: LocalSecuritypolicy.txt
	#>
	[CmdletBinding()]
	param (
		[Parameter(
			Mandatory = $true)]
		[Object]$Path)


	Try {
		Write-Host 'Exporting Local pwdPolicies - LocalSecuritypolicy.txt'
		Write-ACTTDataLog -Message 'Get Local pwdPolicies - LocalSecuritypolicy.txt'
		SecEdit /export /cfg $(Join-Path $Path 'LocalSecuritypolicy.txt') /areas SecurityPolicy
		Write-ACTTDataLog -Message "`tExporting Local pwdPolicies - LocalSecuritypolicy.txt"
		$LocalPwdValues = Import-Csv -Path $(Join-Path $Path 'LocalSecuritypolicy.txt') -Delimiter '=' -Header 'Property', 'Value'
		$colDefLocalPolicy = @()
		$PolicyNeeded = @('MinimumPasswordAge', 'MaximumPasswordAge', 'MinimumPasswordLength', 'PasswordComplexity', 'PasswordHistorySize', 'LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration', 'ClearTextPassword')
		If ($null -ne $LocalPwdValues) {
			ForEach ($Policy in $PolicyNeeded) {

				#Build DomainControllerObject
				$objSP = [PSCustomObject] @{
					'SettingName'  = $Policy
					'SettingValue' = if ($null -ne $($LocalPwdValues | Where-Object { $_.Property -like $($Policy + '*') } | Select-Object -Expand Value)) {
						$LocalPwdValues | Where-Object { $_.Property -like $($Policy + '*') } | Select-Object -Expand Value
					} ELSE {
						'Not Defined'
					}
				}

				$colDefLocalPolicy += $objSP
			}
		} Else {
			ForEach ($Policy in $PolicyNeeded) {
				#Build DomainControllerObject
				$objSP = [PSCustomObject] @{
					'SettingName'  = $Policy
					'SettingValue' = 'Not Defined'
				}
				$colDefLocalPolicy += $objSP
			}
		}
		Write-Host 'Exporting Local pwdPolicies - LocalSecuritypolicy.actt'
		Write-ActtFile -Data $colDefLocalPolicy -Path $(Join-Path $Path 'secpol.actt') -Delimiter $delim

	}

	Catch {
		#Some error occurred attempting to List all Local Policies. Writing error $errorlist
		$swExceptionLog.WriteLine('Error - Could not extract Policy via secedit')
		$swExceptionLog.WriteLine($Error[0])
	}
}



Function Get-LocalDomainGroups {
	<#
	.SYNOPSIS
	Export Get all Local Group Members - LocalDomaingroups

	.DESCRIPTION
	Export Get all Local Group Members - LocalDomaingroups to file
	Report	Fields: 'GroupName', 'GroupSID', 'Member', 'objectSID'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File:
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[String]$Server,
		[Parameter(Mandatory = $true)]
		[Object]$Path)

	Try {

		Write-ACTTDataLog -Message 'Get all Local Group Members - LocalDomaingroups'
		Write-Host 'Searching for All Domain Groups'
		$AllDEntry = [ADSI]"WinNT://$Server"
		$colLocalDomainGroupMembers = @()
		#Loop to get only Groups
		Foreach ($Group in $AllDEntry.Children | Where-Object { $_.SchemaClassName -eq 'group' }) {
			#Loop to get nested groups
			Foreach ($Member in $Group.psbase.invoke('members') | Where-Object { $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null) -eq 'group' }) {
				Try {
					#Check for Empty $Members, if empty create the $objGroup psCustomObject
					if ($null -eq $Member) {
						$objGroup = [PSCustomObject] @{
							'GroupName' = $Group.Name
							'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).value
							'Member'    = ''
							'objectSID' = ''
						}
						$colLocalDomainGroupMembers += $objGroup
					} Else {
						$objGroup = [PSCustomObject] @{
							'GroupName' = $Group.GetType().InvokeMember('Name', 'GetProperty', $null, $Group, $null)
							'GroupSID'  = (New-Object System.Security.Principal.SecurityIdentifier($Group.objectSid.value, 0)).value
							'Member'    = $Member.GetType().InvokeMember('Name', 'GetProperty', $null, $Member, $null)
							'objectSID' = (New-Object System.Security.Principal.SecurityIdentifier($Member.GetType().InvokeMember('objectSid', 'GetProperty', $null, $Member, $null), 0)).value
						}
						$colLocalDomainGroupMembers += $objGroup
					}
				} Catch {
					$swExceptionLog.WriteLine('Error - with the below Domain GroupMember')
					$swExceptionLog.WriteLine($Member)
					$swExceptionLog.WriteLine($Error[0])
					continue
				}
			}
		}
	} Catch {
		#Error occurred attempting to List Nested Groups
		$swExceptionLog.WriteLine('Error - Could not list nested domain groups')
		$swExceptionLog.WriteLine($Error[0])
	}

	$colLocalDomainGroupMembers = $colLocalDomainGroupMembers | Sort-Object Member -Unique

	Get-LocalDomainGroupMembersAll -LocalDomainGroups $colLocalDomainGroupMembers -DomainFQDN (Get-WmiObject win32_computersystem).Domain -Path $Path
}


Function Get-LocalDomainGroupMembersAll {
	<#
	.SYNOPSIS
	Export all nested domain group members in localserver

	.DESCRIPTION
	Export #List all nested domain group members in localserver to file
	Report	Fields: 'GroupName', 'GroupSID' , 'Member' , 'ObjectSID' , 'ObjectType'

	.PARAMETER  Server
	Server to query

	.PARAMETER  Path
	Path to file

	.INPUTS
	None

	.OUTPUTS
		File: localdomaingroupmembers.actt
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[Object]$LocalDomainGroups,
		[Parameter(Mandatory = $true)]
		[String]$DomainFQDN,
		[Parameter(Mandatory = $true)]
		[String]$Path)
	Try {
		Write-ACTTDataLog -Message 'Get all members in Domain Groups - localdomaingroupmembers.actt'
		Write-Host 'Searching for Domain Group Members'
		$colLocalDomainGroupMember = @()

		Foreach ($Group in $LocalDomainGroups) {
			Try {
				$LDAPString = 'LDAP://<SID=' + $Group.objectSID + '>'
				$GroupProp = [adsi]$LDAPString
				if ($null -eq $GroupProp.Member) {
					$objGroupMem = [PSCustomObject] @{
						'GroupName'  = $Group.Member
						'GroupSID'   = $Group.objectSID
						'Member'     = ''
						'objectSID'  = ''
						'objectType' = ''
					}
					$colLocalDomainGroupMember += $objGroupMem
				} Else {
					#Else create a $objGroupMem for each member
					Foreach ($Member in $GroupProp.Member) {
						Try {
							$MemberProp = [ADSI]"LDAP://$Member"
							$objGroupMem = [PSCustomObject] @{
								'GroupName'  = $Group.Member
								'GroupSID'   = $Group.ObjectSID
								'Member'     = $MemberProp.Name
								'objectSID'  = (New-Object System.Security.Principal.SecurityIdentifier $($MemberProp.objectsid), 0).value
								'objectType' = $MemberProp.objectClass
							}
							$colLocalDomainGroupMember += $objGroupMem
						} Catch {
							$swExceptionLog.WriteLine('Error - Issue wth domain group member listing')
							$swExceptionLog.WriteLine($Member)
							$swExceptionLog.WriteLine($Error[0])
						}
					}
				}
			} Catch {
				$swExceptionLog.WriteLine('Error - Issue with Domain Group Listing')
				$swExceptionLog.WriteLine($Group)
				$swExceptionLog.WriteLine($Error[0])
			}
		}

		Write-ActtDataLog -Message "`tExporting Domain Group Members - localdomaingroupmembers.actt"
		Write-Host 'Exporting Domain Group Members - localdomaingroupmembers.actt'
		Write-ActtFile -Data $colLocalDomainGroupMember -Path $(Join-Path $Path 'localdomaingroupmembers.actt') -Delimiter $delim
		#$colLocalDomainGroupMember
	} Catch {
		$swExceptionLog.WriteLine('Error - Could not list all Domain Group Member')
		$swExceptionLog.WriteLine($Error[0])
	}
}


#endregion LocalServerFunctions


Function Get-ADData {
	<#
	.SYNOPSIS
	Export Active Directory Data

	.DESCRIPTION
	Export Active Directory Data to file
	Report	Fields:	'Version'

	.INPUTS
	None

	.OUTPUTS
		File: ADAuditExtract_Version.ACTT
	#>
	# Writing to Data Log
	Write-ACTTDataLog -Message 'Application Starts on DC....'


	$swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'ADAuditExtract_Version.actt'), $false, [System.Text.Encoding]::Unicode)
	$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
	$swVersion.WriteLine($ScriptVersion)
	$swVersion.Close()


	# Check for Elevated Permissions
	$RunningElevated = $null -ne (whoami.exe /all | Select-String S-1-16-12288)
	# $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
	# $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
	# 	if($WindowsPrincipal.IsInRole("Domain Admins"))
	# 	{$RunningElevated = $True}
	#     else
	# 	{$RunningElevated = $false}

	If ($RunningElevated -eq $true) {
		Write-ACTTDataLog -Message '--------Correct Privileges used to run the extractor.--------'
		Write-ACTTConfigSettings -Setting 'PowerShell Version' -Value $psVersion
		Write-ACTTConfigSettings -Setting 'ExtractStartDateAndTime' -Value $ScriptStartTime
		# Get Host and User name currently logged in - HostandUserName.actt
		Get-HostAndUserDetails

		# Get EA Credentials for the AD Forest being audited
		#$Creds = Get-Credential #-Message "Please provide your Enterprise Admin/Domain Admin credentials for AD Forest $ForestFQDN"

		Write-ACTTDataLog -Message "Get EA Credentials for the AD Forest $ForestFQDN"

		$DomainBind = $ForestFQDN


		# Call all functions to query the AD Domain data

		Get-DomainComputersAll -Server $DomainBind -Path $Path
		Get-DomainGroupsAll -Server $DomainBind -Path $Path
		Get-DomainSensitiveGroupMembersAll -Server $DomainBind -Path $Path
		#Get-DomainUsersAll -Server $DomainBind -Path $Path
		Get-DirectoryUsersAll -Server $DomainBind -Path $Path
		Get-DomainUsersStatus -Server $DomainBind -Path $Path
		Get-DomainTrustsLatest -Server $DomainBind -Path $Path
		Get-DCsInDomain -Domain $DomainBind -Path $Path
		Get-DomainPwdPol -Server $ComputerName -Path $Path
		Get-DefDomainPwdPol -Server $ComputerName -Path $Path
		Get-DomainSecPol -Server $ComputerName -Path $Path
		Get-FineGrainedPSO -Path $Path
		Get-DomainSecPolBoolean -Server $DomainBind -Path $Path
		Get-GPOReportall -Server $ComputerName -Path $Path
		Get-ServerUserRights -Server $ComputerName -Path $Path
		Get-DomainGroupsMembersAll -Server $DomainBind -Path $Path
		Get-ServerAuditPolicy -Server $ComputerName -Path $Path
		Get-DomainOUsAll -Server $ComputerName -Path $Path
		Get-OUPermissions -Domain $DomainBind -Path $Path
		Get-ServerQuickFixes -Server $ComputerName -Path $Path

	}

	Else {
		#Write Errors to Log
		Write-ACTTDataLog -Message 'Write Errors to Log'
		$ErrorMesaage = '-------Insufficient Privileges used to run the Extractor.--------'
		$swExceptionLog.WriteLine($ErrorMesaage)
		Write-ACTTDataLog -Message $ErrorMesaage
	}

	# Write ExtractEndTime
	Write-ACTTDataLog -Message 'Script Completed'
	Write-ACTTConfigSettings -Setting 'ExtractEndDateAndTime' -Value $(Get-TimeDate)

}


Function Get-LocalData {
	<#
	.SYNOPSIS
	Export local data

	.DESCRIPTION
	Export local data to file
	Report	Fields:


	.INPUTS
	None

	.OUTPUTS
		File: NDCAuditExtract_Version.ACTT
	#>
	# Writing to Data Log
	Write-ACTTDataLog -Message 'Application Starts on Local Server....'

	$swVersion = New-Object System.IO.StreamWriter($(Join-Path $Path 'NDCAuditExtract_Version.ACTT'), $false, [System.Text.Encoding]::Unicode)
	$swVersion.WriteLine('[Version] NVARCHAR(MAX)')
	$swVersion.WriteLine($ScriptVersion)
	$swVersion.Close()


	# Check for Elevated Permissions
	$RunningElevated = $null -ne (whoami.exe /all | Select-String S-1-16-12288)

	If ($RunningElevated -eq $true) {
		Write-ACTTDataLog -Message '--------Correct Privileges used to run the extractor.--------'
		Write-ACTTConfigSettings -Setting 'PowerShell Version' -Value $psVersion
		Write-ACTTConfigSettings -Setting 'ExtractStartDateAndTime' -Value $ScriptStartTime


		# Get Host and User name currently logged in - HostandUserName.actt
		Get-HostAndUserDetails

		# Get Credentials for the local server being audited
		#$Creds = Get-Credential -Message "Please provide your Local/Domain Admin credentials for this server $ComputerName"

		Write-ACTTDataLog -Message "Get Credentials for local admin $ComputerName"


		Get-LocalGroupsAll -Server $ComputerName -Path $Path
		Get-LocalUsersAll -Server $ComputerName -Path $Path
		Get-LocalWMIUsersAll -Server $ComputerName -Path $Path
		Get-LocalPwdPol -Path $Path
		Get-DomainSecPol -Server $ComputerName -Path $Path
		Get-DomainSecPolBoolean -Server $ComputerName -Path $Path
		Get-LocalDomainGroups -Server $ComputerName -Path $Path

		Get-LocalGroupsMembersAll -Server $ComputerName -Path $Path
		Get-ServerUserRights -Server $ComputerName -Path $Path
		Get-ServerQuickFixes -Server $ComputerName -Path $Path
		Get-ServerAuditPolicy -Server $ComputerName -Path $Path


	}

	Else {
		#Write Errors to Log
		Write-ACTTDataLog -Message 'Write Errors to Log'
		$ErrorMesaage = '-------Insufficient Privileges used to run the Extractor.--------'
		$swExceptionLog.WriteLine($ErrorMesaage)
		Write-ACTTDataLog -Message $ErrorMesaage
	}

	# Write ExtractEndTime
	Write-ACTTDataLog -Message 'Write ExtractEndTime'
	Write-ACTTConfigSettings -Setting 'ExtractEndDateAndTime' -Value $(Get-TimeDate)


}

#endregion Functions


#region Main
Write-Host 'Script analzying the current server environment'
$osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
$psVersion = $PSVersionTable.PSVersion.Major
IF ($osInfo.ProductType -eq '2') {
	Import-Module ActiveDirectory
	# Create a Folder with the Forest name in the Audit Data Path to store the AD Forest audit data
	$Path = Join-Path $Path $ForestFQDN
	New-Item -Path $Path -Type Directory -Force | Out-Null

	# Create ACTTDataLog File
	$swACTTDataLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_DATA.LOG'), $false, [System.Text.Encoding]::Unicode)
	# Create exceptionlog.actt
	$swExceptionLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'exceptionlog.actt'), $false, [System.Text.Encoding]::Unicode)
	$swExceptionLog.WriteLine('[LUMP] NVARCHAR(MAX)')

	# Create ACTT_CONFIG_SETTINGS.actt
	$swConfigSettings = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_SETTINGS.actt'), $false, [System.Text.Encoding]::Unicode)
	$swConfigSettings.WriteLine('SettingName NVARCHAR(MAX)' + $Delim + 'SettingValue NVARCHAR(MAX)')

	# Write ACTT_CONFIG_FIELDTERMINATOR.ACTT
	$swDelim = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_FIELDTERMINATOR.actt'), $false, [System.Text.Encoding]::Unicode)
	$swDelim.WriteLine($Delim)
	$swDelim.Close()
	Write-ACTTDataLog -Message 'Script running on DC'
	Write-Host 'Script running on DC'
	Get-ConfigSettings
	Get-ADData
} Else {

	# Create a Folder with the server name
	$Path = Join-Path $Path $ComputerName
	New-Item -Path $Path -Type Directory -Force | Out-Null

	$swACTTDataLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_DATA.LOG'), $false, [System.Text.Encoding]::Unicode)
	# Create exceptionlog.actt
	$swExceptionLog = New-Object System.IO.StreamWriter($(Join-Path $Path 'exceptionlog.actt'), $false, [System.Text.Encoding]::Unicode)
	$swExceptionLog.WriteLine('[LUMP] NVARCHAR(MAX)')

	# Create ACTT_CONFIG_SETTINGS.actt
	$swConfigSettings = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_SETTINGS.actt'), $false, [System.Text.Encoding]::Unicode)
	$swConfigSettings.WriteLine('SettingName NVARCHAR(MAX)' + $Delim + 'SettingValue NVARCHAR(MAX)')

	# Write ACTT_CONFIG_FIELDTERMINATOR.ACTT
	$swDelim = New-Object System.IO.StreamWriter($(Join-Path $Path 'ACTT_CONFIG_FIELDTERMINATOR.actt'), $false, [System.Text.Encoding]::Unicode)
	$swDelim.WriteLine($Delim)
	$swDelim.Close()
	Write-ACTTDataLog -Message 'Script running on Local Server'
	Write-Host 'Script running on Local Server'
	Get-ConfigSettings
	Get-LocalData
}

#endregion Main

#region CleanUp
Write-ACTTDataLog -Message 'Script Cleanup'
Write-Host 'Script Cleanup'
# Close ACTT_Config_Settings.actt
$swConfigSettings.Close()

# Close exceptionlog.actt
$swExceptionLog.Close()

Write-ACTTDataLog -Message 'Script Completed'
# Close ACTTDataLog File
$swACTTDataLog.Close()
Write-Host 'Script completed'
#endregion CleanUp

################################################################
#
#SIG #Ssignature block needs to be regenerated
################################################################

# SIG # Begin signature block

# SIG # End signature block

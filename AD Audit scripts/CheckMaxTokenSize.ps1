<#
.SYNOPSIS
    Analyzes and reports on Active Directory user token sizes to identify potential authentication issues.

.DESCRIPTION
    This script calculates the Kerberos token size for specified users based on their group memberships and SID history.
    It identifies users at risk of authentication failures due to token size limitations and provides detailed information
    about the components contributing to token bloat.

    The script uses the formula from Microsoft KB327825 to calculate token sizes and can emulate different Windows OS
    versions to determine if token sizes exceed the relevant thresholds.

.PARAMETER Principals
    An array of user principal names or usernames to analyze. Defaults to the current user if not specified.

.PARAMETER OSEmulation
    When set to $true, prompts for which OS token size limit to emulate.
    When set to $false (default), detects the local OS and uses its token size limit.

.PARAMETER Details
    When set to $true, provides detailed information about group memberships and SID history.
    When set to $false (default), provides only summary information.

.EXAMPLE
    .\CheckMaxTokenSize.ps1 -Principals @('FirstName.LastName@YourOrganization.com') -OSEmulation $false -Details $true
    Analyzes token size for a single user with detailed output.

.EXAMPLE
    .\CheckMaxTokenSize.ps1 -Principals @('user1@domain.com', 'user2@domain.com') -Details $true
    Analyzes token size for multiple users with detailed output.

.NOTES
    File Name      : CheckMaxTokenSize.ps1
    Author         : Adapted from TechNet Script Gallery
    Prerequisite   : PowerShell V3, Active Directory PowerShell Module
    Version        : 1.2
    Last Modified  : 2025-04-01

    Updated header and added new Build numbers using switch case

.LINK
    https://support.microsoft.com/kb/327825
#>

PARAM ([array]$Principals = ($env:USERNAME), $OSEmulation = $false, $Details = $false)

Clear-Host

Import-Module ActiveDirectory

Trap [Exception] {
      $Script:ExceptionMessage = $_
      $Error.Clear()
      continue
}

$ExportFile = $pwd.Path + '\' + $env:username + '_TokenSizeDetails.txt'
$global:FormatEnumerationLimit = -1

'Token Details for all Users' | Out-File -FilePath $ExportFile
'********************' | Out-File -FilePath $ExportFile -Append
"`n" | Out-File $ExportFile -Append

#If OS is not specified to hypothesize token size let's find the local OS and computer role
if ($OSEmulation -eq $false) {
      try {
            $OS = Get-WmiObject -Class Win32_OperatingSystem
      } catch {
            $OS = Get-CimInstance -Class Win32_OperatingSystem
      }
      try {

            $cs = Get-WmiObject -Namespace 'root\cimv2' -Class win32_computersystem
      } catch {
            <#Do this if a terminating exception happens#>
            $cs = Get-CimInstance -Namespace 'root\cimv2' -Class win32_computersystem
      }

      $DomainRole = $cs.DomainRole
      switch -regex ($DomainRole) {
            [0-1] {
                  #Workstation.
                  $RoleString = 'client'

                  switch ($OS.BuildNumber) {
                        3790 {
                              $OperatingSystem = 'Windows XP'
                              $OSBuild = $OS.BuildNumber
                        }
                        6001 {
                              $OperatingSystem = 'Windows Vista'
                              $OSBuild = $OS.BuildNumber

                        }
                        6002 {
                              $OperatingSystem = 'Windows Vista'
                              $OSBuild = $OS.BuildNumber

                        }
                        { ($_ -eq 10240) -or ($_ -eq 10586) } {
                              $OperatingSystem = 'Windows 7'
                              $OSBuild = $OS.BuildNumber
                        }
                        9600 {
                              $OperatingSystem = 'Windows 8.1'
                              $OSBuild = $OS.BuildNumber
                        }

                        { ($_ -eq 10240) -or ($_ -eq 10586) -or ($_ -eq 14393) -or ($_ -eq 15063) -or ($_ -eq 16299) -or ($_ -eq 17134) -or ($_ -eq 17763) -or ($_ -eq 18362) -or ($_ -eq 18363) -or ($_ -eq 19041) -or ($_ -eq 19042) -or ($_ -eq 19043) -or ($_ -eq 19044) -or ($_ -eq 19045) -or ($_ -eq 10586)

                        } {
                              $OperatingSystem = 'Windows 10'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 2200) -or ($_ -eq 22621) -or ($_ -eq 22631) -or ($_ -eq 26100)
                        } {
                              $OperatingSystem = 'Windows 11'
                              $OSBuild = $OS.BuildNumber
                        }
                        default {
                              $OperatingSystem = 'Unknown'
                              $OSBuild = '00'
                        }
                  }
            }
            [2-3] {
                  #Member server.
                  $RoleString = 'member server'
                  switch ($OS.BuildNumber) {
                        3790 {
                              $OperatingSystem = 'Windows Server 2003'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 6001) -or ($_ -eq 6002) } {
                              $OperatingSystem = 'Windows Server 2008'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 7600) -or ($_ -eq 7601) } {
                              $OperatingSystem = 'Windows Server 2008 R2'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 9200) } {
                              $OperatingSystem = 'Windows Server 2012'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2012 R2'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 14393) -or ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2016'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 17763) } {
                              $OperatingSystem = 'Windows Server 2019'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 220348) } {
                              $OperatingSystem = 'Windows Server 2022'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 26100) -or ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2025'
                              $OSBuild = $OS.BuildNumber
                        }
                  }
            }
            [4-5] {
                  #Domain Controller
                  $RoleString = 'domain controller'
                  switch ($OS.BuildNumber) {
                        3790 {
                              $OperatingSystem = 'Windows Server 2003'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 6001) -or ($_ -eq 6002) } {
                              $OperatingSystem = 'Windows Server 2008'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 7600) -or ($_ -eq 7601) } {
                              $OperatingSystem = 'Windows Server 2008 R2'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 9200) } {
                              $OperatingSystem = 'Windows Server 2012'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2012 R2'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 14393) -or ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2016'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 17763) } {
                              $OperatingSystem = 'Windows Server 2019'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 220348) } {
                              $OperatingSystem = 'Windows Server 2022'
                              $OSBuild = $OS.BuildNumber
                        }
                        { ($_ -eq 26100) -or ($_ -eq 9600) } {
                              $OperatingSystem = 'Windows Server 2025'
                              $OSBuild = $OS.BuildNumber
                        }
                  }
            }
      }
}

if ($OSEmulation -eq $true) {
      #Prompt user to choose which OS since they chose to emulate.
      $PromptTitle = 'Operating System'
      $Message = 'Select which operating system to emulate for token sizing (size tolerance is and configuration OS dependant).'
      $12K = New-Object System.Management.Automation.Host.ChoiceDescription 'Gauge Kerberos token size using the Windows 7/Windows Server 2008 R2 and earlier default token size of &12K.'
      $48K = New-Object System.Management.Automation.Host.ChoiceDescription 'Gauge Kerberos token size using the Windows 8/Windows Server 2012 default token size of &48K. Note: The &48K setting is optionally configurable for many earlier Windows versions.'
      $65K = New-Object System.Management.Automation.Host.ChoiceDescription 'Gauge Kerberos token size using the Windows 10 and later default token size of &65K. Note: The &65K setting is optionally configurable for many earlier Windows versions.'
      $OSOptions = [System.Management.Automation.Host.ChoiceDescription[]]($12K, $48K, $65K)
      $Result = $Host.UI.PromptForChoice($PromptTitle, $Message, $OSOptions, 0)
      switch ($Result) {
            0 {
                  $OSBuild = '7600'
                  'Gauging Kerberos token size using the Windows 7/Windows Server 2008 R2 and earlier default token size of 12K.' | Out-File $ExportFile -Append
                  Write-Host 'Gauging Kerberos token size using the Windows 7/Windows Server 2008 R2 and earlier default token size of 12K.'
            }
            1 {
                  $OSBuild = '9200'
                  'Gauging Kerberos token size using the Windows 8/Windows Server 2012 and later default token size of 48K. Note: The 48K setting is optionally configurable for many earlier Windows versions.' | Out-File $ExportFile -Append
                  Write-Host 'Gauging Kerberos token size using the Windows 8/Windows Server 2012 and later default token size of 48K. Note: The 48K setting is optionally configurable for many earlier Windows versions.'
            }
            2 {
                  $OSBuild = '10586'
                  'Gauging Kerberos token size using the Windows 10 default token size of 65K. Note: The 65K setting is optionally configurable for many earlier Windows versions.' | Out-File $ExportFile -Append
                  Write-Host 'Gauging Kerberos token size using the Windows 8/Windows Server 2012 and later default token size of 65K. Note: The 65K setting is optionally configurable for many earlier Windows versions.'
            }
      }
} else {
      Write-Host "The computer is $OperatingSystem and is a $RoleString."
      "The computer is $OperatingSystem and is a $RoleString." | Out-File $ExportFile -Append
}

function GetSIDHistorySIDs {
      param ([string]$ObjectName)
      Trap [Exception] {
            $Script:ExceptionMessage = $_
            $Error.Clear()
            continue
      }
      $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
      $RootString = 'LDAP://' + $DomainInfo.Name
      $Root = New-Object System.DirectoryServices.DirectoryEntry($RootString)
      $searcher = New-Object DirectoryServices.DirectorySearcher($Root)
      $searcher.Filter = "(|(UserPrincipalName=$ObjectName)(name=$ObjectName))"
      $results = $searcher.FindOne()
      if ($null -ne $results) {
            $SIDHistoryResults = $results.properties.sidhistory
      }
      #Clean up the SIDs so they are formatted correctly
      $SIDHistorySids = @()
      foreach ($SIDHistorySid in $SIDHistoryResults) {
            $SIDString = (New-Object System.Security.Principal.SecurityIdentifier($SIDHistorySid, 0)).Value
            $SIDHistorySids += $SIDString
      }
      return $SIDHistorySids
}

foreach ($Principal in $Principals) {
      #Obtain domain SID for group SID comparisons.
      $UserIdentity = New-Object System.Security.Principal.WindowsIdentity($Principal)
      $Groups = $UserIdentity.get_Groups()
      $DomainSID = $UserIdentity.User.AccountDomainSid
      $GroupCount = $Groups.Count
      if ($Details -eq $true) {
            $GroupDetails = New-Object PSObject
            Write-Progress -Activity 'Getting SIDHistory, and group details for review.' -Status 'Detailed results requested. This may take awhile.' -ErrorAction SilentlyContinue
      }

      $AllGroupSIDHistories = @()
      $SecurityGlobalScope = 0
      $SecurityDomainLocalScope = 0
      $SecurityUniversalInternalScope = 0
      $SecurityUniversalExternalScope = 0

      foreach ($GroupSid in $Groups) {
            $Group = [adsi]"LDAP://<SID=$GroupSid>"
            $GroupType = $Group.groupType
            if ($null -ne $Group.name) {
                  $SIDHistorySids = GetSIDHistorySIDs $Group.name
                  If (($SIDHistorySids | Measure-Object).Count -gt 0) {
                        $AllGroupSIDHistories += $SIDHistorySids
                  }
                  $GroupName = $Group.name.ToString()

                  #Resolve SIDHistories if possible to give more detail.
                  if (($Details -eq $true) -and ($null -ne $SIDHistorySids)) {
                        $GroupSIDHistoryDetails = New-Object PSObject
                        foreach ($GroupSIDHistory in $AllGroupSIDHistories) {
                              $SIDHistGroup = New-Object System.Security.Principal.SecurityIdentifier($GroupSIDHistory)
                              $SIDHistGroupName = $SIDHistGroup.Translate([System.Security.Principal.NTAccount])
                              $GroupSIDHISTString = $GroupName + '--> ' + $SIDHistGroupName
                              Add-Member -InputObject $GroupSIDHistoryDetails -MemberType NoteProperty -Name $GroupSIDHistory -Value $GroupSIDHISTString -Force
                        }
                  }
            }

            #Count number of security groups in different scopes.
            switch -exact ($GroupType) {
                  '-2147483646' {
                        #Domain Global scope
                        $SecurityGlobalScope++
                        if ($Details -eq $true) {
                              #Domain Global scope
                        				  $GroupNameString = $GroupName + ' (' + ($GroupSID.ToString()) + ')'
                        				  Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString -Value 'Domain Global Group'
                              $GroupNameString = $null
                        }
                  }
                  '-2147483644' {
                        #Domain Local scope
                        $SecurityDomainLocalScope++
                        if ($Details -eq $true) {
                        				  $GroupNameString = $GroupName + ' (' + ($GroupSID.ToString()) + ')'
                        				  Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString -Value 'Domain Local Group'
                       					  $GroupNameString = $null
                        }
                  }
                  '-2147483640' {
                        #Universal scope; must separate local
                        #domain universal groups from others.
                        if ($GroupSid -match $DomainSID) {
                              $SecurityUniversalInternalScope++
                              if ($Details -eq $true) {
                                    $GroupNameString = $GroupName + ' (' + ($GroupSID.ToString()) + ')'
                                    Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString -Value 'Local Universal Group'
                                    $GroupNameString = $null
                              }
                        } else {
                              $SecurityUniversalExternalScope++
                              if ($Details -eq $true) {
                                    $GroupNameString = $GroupName + ' (' + ($GroupSID.ToString()) + ')'
                                    Add-Member -InputObject $GroupDetails -MemberType NoteProperty -Name $GroupNameString -Value 'External Universal Group'
                                    $GroupNameString = $null
                              }
                        }
                  }
            }

      }

      #Get user object SIDHistories
      $SIDHistoryResults = GetSIDHistorySIDs $Principal
      $SIDCounter = $SIDHistoryResults.count

      #Resolve SIDHistories if possible to give more detail.
      if (($Details -eq $true) -and ($null -ne $SIDHistoryResults)) {
            $UserSIDHistoryDetails = New-Object PSObject
            foreach ($SIDHistory in $SIDHistoryResults) {
                  $SIDHist = New-Object System.Security.Principal.SecurityIdentifier($SIDHistory)
                  $SIDHistName = $SIDHist.Translate([System.Security.Principal.NTAccount])
                  Add-Member -InputObject $UserSIDHistoryDetails -MemberType NoteProperty -Name $SIDHistName -Value $SIDHistory -Force
            }
      }

      $GroupSidHistoryCounter = $AllGroupSIDHistories.Count
      $AllSIDHistories = $SIDCounter + $GroupSidHistoryCounter

      #Calculate the current token size.
      $TokenSize = 0 #Set to zero in case the script is *gasp* ran twice in the same PS.
      $TokenSize = 1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $GroupSidHistoryCounter)) + (8 * ($SecurityGlobalScope + $SecurityUniversalInternalScope))
      $DelegatedTokenSize = 2 * (1200 + (40 * ($SecurityDomainLocalScope + $SecurityUniversalExternalScope + $GroupSidHistoryCounter)) + (8 * ($SecurityGlobalScope + $SecurityUniversalInternalScope)))
      #Begin output of details regarding the user into prompt and outfile.
      "`n" | Out-File $ExportFile -Append
      Write-Host ' '
      Write-Host "Token Details for user $Principal"
      "Token Details for user $Principal" | Out-File $ExportFile -Append
      Write-Host '**********************************'
      '**********************************' | Out-File $ExportFile -Append
      $Username = $UserIdentity.name
      $PrincipalsDomain = $Username.Split('\')[0]
      Write-Host "User's domain is $PrincipalsDomain."
      "User's domain is $PrincipalsDomain." | Out-File $ExportFile -Append

      Write-Host "Total estimated token size is $TokenSize."
      "Total estimated token size is $TokenSize." | Out-File $ExportFile -Append

      Write-Host "For access to DCs and delegatable resources the total estimated token delegation size is $DelegatedTokenSize."
      "For access to DCs and delegatable resources the total estimated token delegation size is $DelegatedTokenSize." | Out-File $ExportFile -Append

      $KerbKey = Get-Item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters
      $MaxTokenSizeValue = $KerbKey.GetValue('MaxTokenSize')
      if ($null -eq $MaxTokenSizeValue) {
            if ($OSBuild -lt 9200) {
                  $MaxTokenSizeValue = 12000
            }
            if ($OSBuild -ge 9200) {
                  $MaxTokenSizeValue = 48000
            }
      }
      Write-Host "Effective MaxTokenSize value is: $MaxtokenSizeValue"
      "Effective MaxTokenSize value is: $MaxtokenSizeValue" | Out-File $ExportFile -Append

      #Assess OS so we can alert based on default for proper OS version. Windows 8 and Server 2012 allow for a larger token size safely.
      #$ProblemDetected = $false
      if (($OSBuild -lt 9200) -and (($TokenSize -ge 12000) -or ((($TokenSize -gt $MaxTokenSizeValue) -or ($DelegatedTokenSize -gt $MaxTokenSizeValue)) -and ($null -ne $MaxTokenSizeValue)))) {
            Write-Host 'Problem detected. The token was too large for consistent authorization. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships.' -ForegroundColor 'red'
      } elseif ((($OSBuild -eq 9200) -or ($OSBuild -eq 9600)) -and (($TokenSize -ge 48000) -or ((($TokenSize -gt $MaxTokenSizeValue) -or ($DelegatedTokenSize -gt $MaxTokenSizeValue)) -and ($null -ne $MaxTokenSizeValue)))) {
            Write-Host 'Problem detected. The token was too large for consistent authorization. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships.' -ForegroundColor 'red'
      } elseif (($OSBuild -eq 10586) -and (($TokenSize -ge 65535) -or ((($TokenSize -gt $MaxTokenSizeValue) -or ($DelegatedTokenSize -gt $MaxTokenSizeValue)) -and ($null -ne $MaxTokenSizeValue)))) {
            Write-Host 'WARNING: The token was large enough that it may have problems when being used for Kerberos delegation or for access to Active Directory domain controller services. Alter the maximum size per KB http://support.microsoft.com/kb/327825 and consider reducing direct and transitive group memberships.' -ForegroundColor 'yellow'
      } else {
            Write-Host 'Problem not detected.' -BackgroundColor 'green'

      }

      if ($Details -eq $true) {
            "`n" | Out-File $ExportFile -Append
            Write-Host ' '
            Write-Host "*Token Details for $principal*"
            '*Token Details*' | Out-File $ExportFile -Append
            Write-Host "There are $GroupCount groups in the token."
            "There are $GroupCount groups in the token." | Out-File $ExportFile -Append
            Write-Host "There are $SIDCounter SIDs in the users SIDHistory."
            "There are $SIDCounter SIDs in the users SIDHistory." | Out-File $ExportFile -Append
            Write-Host "There are $GroupSidHistoryCounter SIDs in the users groups SIDHistory attributes."
            "There are $GroupSidHistoryCounter SIDs in the users groups SIDHistory attributes." | Out-File $ExportFile -Append
            Write-Host "There are $AllSIDHistories total SIDHistories for user and groups user is a member of."
            "There are $AllSIDHistories total SIDHistories for user and groups user is a member of." | Out-File $ExportFile -Append
            Write-Host "$SecurityGlobalScope are domain global scope security groups."
            "$SecurityDomainLocalScope are domain local security groups." | Out-File $ExportFile -Append
            Write-Host "$SecurityDomainLocalScope are domain local security groups."
            "$SecurityUniversalInternalScope are universal security groups inside of the users domain." | Out-File $ExportFile -Append
            Write-Host "$SecurityUniversalInternalScope are universal security groups inside of the users domain."
            "$SecurityUniversalExternalScope are universal security groups outside of the users domain." | Out-File $ExportFile -Append
            Write-Host "$SecurityUniversalExternalScope are universal security groups outside of the users domain."

            Write-Host "Summary and all other token content details can be found in the output file at $ExportFile"
            "`n" | Out-File $ExportFile -Append
            'Group Details' | Out-File $ExportFile -Append
            $GroupDetails | Format-List * | Out-File -FilePath $ExportFile -Width 500 -Append
            "`n" | Out-File $ExportFile -Append

            'Group SIDHistory Details' | Out-File $ExportFile -Append
            if ($null -eq $GroupSIDHistoryDetails) {
                  '[NONE FOUND]' | Out-File $ExportFile -Append
            } else {
                  $GroupSIDHistoryDetails | Format-List * | Out-File -FilePath $ExportFile -Width 500 -Append
            }
            "`n" | Out-File $ExportFile -Append
            'User SIDHistory Details' | Out-File $ExportFile -Append
            if ($null -eq $UserSIDHistoryDetails) {
                  '[NONE FOUND]' | Out-File $ExportFile -Append
            } else {
                  $UserSIDHistoryDetails | Format-List * | Out-File -FilePath $ExportFile -Width 500 -Append
            }
            "`n" | Out-File $ExportFile -Append

      }

}

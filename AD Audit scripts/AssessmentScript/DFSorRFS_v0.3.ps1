<#
.SYNOPSIS
    Checks whether a domain is using FRS or DFS-R for SYSVOL replication.

.DESCRIPTION
    This script determines the replication method used for SYSVOL in an Active Directory domain.
    It checks for the presence of FRS (File Replication Service) or DFS-R (Distributed File System Replication)
    configuration objects in Active Directory.

.PARAMETER DomainName
    Specifies the domain to check. If not provided, uses the current computer's domain.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'Text', 'Object', 'JSON'. Default is 'Text'.

.PARAMETER OutputFile
    Specifies a file path to save the results. If not provided, displays results on console.

.EXAMPLE
    .\DFSorRFS_v1.0.ps1
    Checks the current domain's replication method.

.EXAMPLE
    .\DFSorRFS_v1.0.ps1 -DomainName "contoso.com" -OutputFormat Object
    Checks the specified domain and returns an object with detailed information.

.EXAMPLE
    .\DFSorRFS_v1.0.ps1 -OutputFile "C:\Reports\sysvol-replication.json" -OutputFormat JSON
    Saves results to a JSON file.

.NOTES
    Version: 1.0
    Author: Updated with modern PowerShell practices
    Last Modified: February 2026
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Domain name to check")]
    [string]$DomainName,

    [Parameter(Mandatory = $false, HelpMessage = "Output format")]
    [ValidateSet('Text', 'Object', 'JSON')]
    [string]$OutputFormat = 'Text',

    [Parameter(Mandatory = $false, HelpMessage = "Output file path")]
    [string]$OutputFile
)

# Requires PowerShell 3.0 or higher for best compatibility
#Requires -Version 3.0
#Requires -Modules ActiveDirectory

function Test-SysvolReplication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainName
    )

    try {
        # Import ActiveDirectory module if not already loaded
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Verbose "ActiveDirectory module imported successfully."
        }

        # Get domain information
        if ([string]::IsNullOrEmpty($DomainName)) {
            $domain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
            $DomainName = $domain.Name
            Write-Verbose "Using local domain: $DomainName"
        } else {
            $domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
            Write-Verbose "Using specified domain: $DomainName"
        }

        # Construct distinguished names for FRS and DFSR objects
        $domainDN = $domain.DistinguishedName
        $FRSsysvol = "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,$domainDN"
        $DFSRsysvol = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN"

        Write-Verbose "Checking for FRS object: $FRSsysvol"
        Write-Verbose "Checking for DFSR object: $DFSRsysvol"

        # Check for replication service objects
        $frsObject = $null
        $dfsrObject = $null

        try {
            $frsObject = Get-ADObject -Filter { distinguishedName -eq $FRSsysvol } -Server $DomainName -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "FRS object not found or error accessing: $($_.Exception.Message)"
        }

        try {
            $dfsrObject = Get-ADObject -Filter { distinguishedName -eq $DFSRsysvol } -Server $DomainName -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "DFSR object not found or error accessing: $($_.Exception.Message)"
        }

        # Determine replication method and create result object
        $result = [PSCustomObject]@{
            DomainName = $DomainName
            DomainDN = $domainDN
            ReplicationMethod = 'Unknown'
            Status = 'Unknown'
            FRSObjectExists = $null -ne $frsObject
            DFSRObjectExists = $null -ne $dfsrObject
            CheckDate = Get-Date
            Recommendation = ''
            SecurityImplications = ''
            PerformanceNotes = ''
        }

        if ($null -ne $frsObject -and $null -eq $dfsrObject) {
            $result.ReplicationMethod = 'FRS'
            $result.Status = 'Legacy'
            $result.Recommendation = 'CRITICAL: Migrate to DFS-R immediately for better performance, reliability, and security'
            $result.SecurityImplications = 'FRS is deprecated and has known security vulnerabilities'
            $result.PerformanceNotes = 'FRS can cause significant performance issues and data inconsistencies'
        }
        elseif ($null -eq $frsObject -and $null -ne $dfsrObject) {
            $result.ReplicationMethod = 'DFS-R'
            $result.Status = 'Modern'
            $result.Recommendation = 'Current configuration is recommended and follows best practices'
            $result.SecurityImplications = 'DFS-R provides secure and reliable replication'
            $result.PerformanceNotes = 'DFS-R offers efficient bandwidth usage and robust conflict resolution'
        }
        elseif ($null -ne $frsObject -and $null -ne $dfsrObject) {
            $result.ReplicationMethod = 'Mixed'
            $result.Status = 'Transition'
            $result.Recommendation = 'Migration appears to be in progress - verify configuration and complete migration'
            $result.SecurityImplications = 'Mixed state may present security risks - complete migration promptly'
            $result.PerformanceNotes = 'Mixed configuration may cause replication conflicts'
        }
        else {
            $result.ReplicationMethod = 'Unknown'
            $result.Status = 'Error'
            $result.Recommendation = 'Unable to determine replication method - investigate domain controller connectivity and AD health'
            $result.SecurityImplications = 'Unknown configuration presents potential security risks'
            $result.PerformanceNotes = 'Cannot assess performance without knowing replication method'
        }

        return $result

    } catch {
        throw "Error checking SYSVOL replication: $($_.Exception.Message)"
    }
}

# Main execution
try {
    $result = Test-SysvolReplication -DomainName $DomainName

    # Output results based on format
    switch ($OutputFormat) {
        'Text' {
            $color = switch ($result.ReplicationMethod) {
                'FRS' { 'Red' }
                'DFS-R' { 'Green' }
                'Mixed' { 'Yellow' }
                default { 'Red' }
            }

            Write-Host "`nSYSVOL Replication Analysis" -ForegroundColor Cyan
            Write-Host "=========================" -ForegroundColor Cyan
            Write-Host "Domain: " -NoNewline
            Write-Host $result.DomainName -ForegroundColor White
            Write-Host "Replication Method: " -NoNewline
            Write-Host $result.ReplicationMethod -ForegroundColor $color
            Write-Host "Status: " -NoNewline
            Write-Host $result.Status -ForegroundColor $color
            Write-Host "Check Date: " -NoNewline
            Write-Host $result.CheckDate -ForegroundColor Gray

            Write-Host "`nAnalysis:" -ForegroundColor Yellow
            Write-Host "FRS Object Exists: $($result.FRSObjectExists)" -ForegroundColor Gray
            Write-Host "DFSR Object Exists: $($result.DFSRObjectExists)" -ForegroundColor Gray

            if ($result.Recommendation) {
                Write-Host "`nRecommendation:" -ForegroundColor Yellow
                Write-Host $result.Recommendation -ForegroundColor White
            }

            if ($result.SecurityImplications) {
                Write-Host "`nSecurity Implications:" -ForegroundColor Magenta
                Write-Host $result.SecurityImplications -ForegroundColor White
            }

            if ($result.PerformanceNotes) {
                Write-Host "`nPerformance Notes:" -ForegroundColor Cyan
                Write-Host $result.PerformanceNotes -ForegroundColor White
            }
        }

        'Object' {
            $outputResult = $result
        }

        'JSON' {
            $outputResult = $result | ConvertTo-Json -Depth 2
        }
    }

    # Save to file if specified
    if ($OutputFile) {
        $outputDir = Split-Path $OutputFile -Parent
        if ($outputDir -and -not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        switch ($OutputFormat) {
            'Text' {
                $textOutput = @"
SYSVOL Replication Analysis
=========================
Domain: $($result.DomainName)
Replication Method: $($result.ReplicationMethod)
Status: $($result.Status)
Check Date: $($result.CheckDate)

Analysis:
FRS Object Exists: $($result.FRSObjectExists)
DFSR Object Exists: $($result.DFSRObjectExists)

Recommendation:
$($result.Recommendation)

Security Implications:
$($result.SecurityImplications)

Performance Notes:
$($result.PerformanceNotes)
"@
                $textOutput | Out-File -FilePath $OutputFile -Encoding UTF8
            }

            'Object' {
                $result | Export-Clixml -Path $OutputFile
            }

            'JSON' {
                $result | ConvertTo-Json -Depth 2 | Out-File -FilePath $OutputFile -Encoding UTF8
            }
        }

        Write-Host "`nResults saved to: $OutputFile" -ForegroundColor Green
    }

    if ($OutputFormat -in @('Object', 'JSON') -and -not $OutputFile) {
        return $outputResult
    }

} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}

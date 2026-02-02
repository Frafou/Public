<#
.SYNOPSIS
    Enumerates DNS zones from all domain controllers in the Active Directory domain.

.DESCRIPTION
    This script connects to all domain controllers in the current AD domain and retrieves
    comprehensive DNS zone information including zone names, types, storage methods,
    properties, and additional zone details. Supports multiple output formats and
    provides enterprise-ready error handling and reporting capabilities.

.PARAMETER DomainName
    Specifies the domain to query. If not provided, uses the current computer's domain.

.PARAMETER OutputPath
    Specifies the output directory for the result files. Default is current directory.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'CSV', 'JSON', 'Excel', 'Object'. Default is 'CSV'.

.PARAMETER IncludeForwarders
    Include DNS forwarder information in the output.

.PARAMETER IncludeZoneDetails
    Include additional zone details like record counts and zone health status.

.PARAMETER UseModernDNS
    Use modern PowerShell DNS cmdlets instead of legacy dnscmd for better reliability.

.PARAMETER Credential
    Specifies credentials to use when connecting to domain controllers.

.PARAMETER TimeoutSeconds
    Timeout in seconds for DNS queries. Default is 60 seconds.

.EXAMPLE
    .\DNSZone_v2.0.ps1
    Enumerates DNS zones from all DCs in current domain and saves to CSV.

.EXAMPLE
    .\DNSZone_v2.0.ps1 -OutputFormat JSON -IncludeForwarders -OutputPath "C:\Reports"
    Enumerates zones including forwarders and saves as JSON to specified path.

.EXAMPLE
    .\DNSZone_v2.0.ps1 -UseModernDNS -IncludeZoneDetails -Credential (Get-Credential)
    Uses modern DNS cmdlets with zone details using specified credentials.

.EXAMPLE
    .\DNSZone_v2.0.ps1 -OutputFormat Object | Where-Object {$_.ZoneType -eq 'Primary'}
    Returns zone objects for further PowerShell processing, filtering primary zones.

.NOTES
    Version: 2.0
    Author: Updated with modern PowerShell practices
    Last Modified: February 2026
    Requires: PowerShell 5.1 or higher, ActiveDirectory module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Domain name to query")]
    [string]$DomainName,

    [Parameter(Mandatory = $false, HelpMessage = "Output directory path")]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false, HelpMessage = "Output format")]
    [ValidateSet('CSV', 'JSON', 'Excel', 'Object')]
    [string]$OutputFormat = 'CSV',

    [Parameter(Mandatory = $false, HelpMessage = "Include DNS forwarder information")]
    [switch]$IncludeForwarders,

    [Parameter(Mandatory = $false, HelpMessage = "Include additional zone details")]
    [switch]$IncludeZoneDetails,

    [Parameter(Mandatory = $false, HelpMessage = "Use modern PowerShell DNS cmdlets")]
    [switch]$UseModernDNS,

    [Parameter(Mandatory = $false, HelpMessage = "Credentials for domain controller access")]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false, HelpMessage = "Timeout for DNS queries")]
    [int]$TimeoutSeconds = 60
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

function Get-DNSZoneInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeForwarders,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeZoneDetails,

        [Parameter(Mandatory = $false)]
        [switch]$UseModernDNS,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 60
    )

    $zoneResults = @()

    try {
        Write-Verbose "Connecting to domain controller: $ComputerName"

        # Test connectivity first
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            throw "Computer $ComputerName is not reachable via network"
        }

        # Try modern PowerShell DNS cmdlets first if requested
        if ($UseModernDNS) {
            try {
                Write-Verbose "Using modern PowerShell DNS cmdlets"

                $scriptBlock = {
                    param($IncludeForwarders, $IncludeZoneDetails)

                    $zones = @()

                    # Get DNS zones using PowerShell cmdlets (Windows Server 2012+)
                    $dnsZones = Get-DnsServerZone -ErrorAction Stop

                    foreach ($zone in $dnsZones) {
                        $zoneObj = [PSCustomObject]@{
                            Computer = $env:COMPUTERNAME
                            Name = $zone.ZoneName
                            ZoneType = $zone.ZoneType
                            Storage = if ($zone.IsAutoCreated) { "Auto" } elseif ($zone.IsDsIntegrated) { "AD" } else { "File" }
                            Properties = @()
                            IsReverseLookup = $zone.IsReverseLookupZone
                            IsSigned = $zone.IsSigned
                            DynamicUpdate = $zone.DynamicUpdate
                            ZoneFile = $zone.ZoneFile
                            Method = "PowerShell"
                            ErrorMessage = $null
                            Status = "Success"
                            CollectionTime = Get-Date
                        }

                        # Add properties
                        $properties = @()
                        if ($zone.IsDsIntegrated) { $properties += "DS" }
                        if ($zone.IsAutoCreated) { $properties += "Auto" }
                        if ($zone.IsSigned) { $properties += "Signed" }
                        if ($zone.DynamicUpdate -ne "None") { $properties += "Update" }
                        if ($zone.IsReverseLookupZone) { $properties += "Reverse" }

                        $zoneObj.Properties = $properties

                        # Add zone details if requested
                        if ($IncludeZoneDetails) {
                            try {
                                $zoneStats = Get-DnsServerZoneStatistics -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue
                                if ($zoneStats) {
                                    $zoneObj | Add-Member -NotePropertyName 'RecordCount' -NotePropertyValue $zoneStats.ZoneTransferReceived
                                    $zoneObj | Add-Member -NotePropertyName 'SerialNumber' -NotePropertyValue $zoneStats.SerialNumber
                                }
                            } catch {
                                Write-Verbose "Could not get zone statistics for $($zone.ZoneName): $($_.Exception.Message)"
                            }
                        }

                        $zones += $zoneObj
                    }

                    # Get forwarders if requested
                    if ($IncludeForwarders) {
                        try {
                            $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
                            if ($forwarders -and $forwarders.IPAddress) {
                                $forwarderObj = [PSCustomObject]@{
                                    Computer = $env:COMPUTERNAME
                                    Name = "Forwarders"
                                    ZoneType = "Forwarder"
                                    Storage = "Config"
                                    Properties = ($forwarders.IPAddress.IPAddressToString -join ", ")
                                    IsReverseLookup = $false
                                    IsSigned = $false
                                    DynamicUpdate = "None"
                                    ZoneFile = "N/A"
                                    Method = "PowerShell"
                                    ErrorMessage = $null
                                    Status = "Success"
                                    CollectionTime = Get-Date
                                }
                                $zones += $forwarderObj
                            }
                        } catch {
                            Write-Warning "Could not retrieve forwarders: $($_.Exception.Message)"
                        }
                    }

                    return $zones
                }

                # Execute the script block
                $invokeParams = @{
                    ScriptBlock = $scriptBlock
                    ArgumentList = $IncludeForwarders, $IncludeZoneDetails
                }

                if ($ComputerName -ne $env:COMPUTERNAME) {
                    $invokeParams.ComputerName = $ComputerName
                    if ($Credential) {
                        $invokeParams.Credential = $Credential
                    }
                }

                $zoneResults = Invoke-Command @invokeParams

                Write-Verbose "Successfully retrieved $($zoneResults.Count) zones using PowerShell cmdlets from $ComputerName"
                return $zoneResults

            } catch {
                Write-Warning "PowerShell DNS cmdlets failed on $ComputerName, falling back to dnscmd: $($_.Exception.Message)"
            }
        }

        # Fallback to dnscmd method
        Write-Verbose "Using legacy dnscmd method"

        $dnscmdExpression = "dnscmd $ComputerName /enumzones"
        $dnscmdOut = Invoke-Expression $dnscmdExpression 2>$null

        if ($LASTEXITCODE -ne 0 -or -not $dnscmdOut) {
            throw "dnscmd failed with exit code: $LASTEXITCODE"
        }

        # Check for successful completion
        $successLine = $dnscmdOut | Where-Object { $_ -match "Command completed successfully" }
        if (-not $successLine) {
            throw "dnscmd did not complete successfully"
        }

        # Find header line
        $headerIndex = -1
        for ($i = 0; $i -lt $dnscmdOut.Count; $i++) {
            if ($dnscmdOut[$i] -match "Zone name.*Type.*Storage.*Properties") {
                $headerIndex = $i
                break
            }
        }

        if ($headerIndex -lt 0) {
            throw "Could not find zone header in dnscmd output"
        }

        $zoneHeader = $dnscmdOut[$headerIndex]
        $d1 = $zoneHeader.IndexOf("Zone name")
        $d2 = $zoneHeader.IndexOf("Type")
        $d3 = $zoneHeader.IndexOf("Storage")
        $d4 = $zoneHeader.IndexOf("Properties")

        # Process zone data
        $zoneLines = $dnscmdOut[($headerIndex + 2)..($dnscmdOut.Count - 3)] | Where-Object { $_.Trim() -ne "" }

        foreach ($zoneLine in $zoneLines) {
            if ($zoneLine.Trim().Length -gt 0 -and $d4 -lt $zoneLine.Length) {
                try {
                    $zoneName = $zoneLine.SubString($d1, $d2 - $d1).Trim()
                    $zoneType = $zoneLine.SubString($d2, $d3 - $d2).Trim()
                    $storage = $zoneLine.SubString($d3, $d4 - $d3).Trim()
                    $properties = $zoneLine.SubString($d4).Trim()

                    $zoneObj = [PSCustomObject]@{
                        Computer = $ComputerName
                        Name = $zoneName
                        ZoneType = $zoneType
                        Storage = $storage
                        Properties = ($properties -split "\s+") -join ", "
                        IsReverseLookup = $zoneName -match "\.in-addr\.arpa|\.ip6\.arpa"
                        IsSigned = $properties -match "Signed"
                        DynamicUpdate = if ($properties -match "Update") { "Secure" } else { "None" }
                        ZoneFile = if ($storage -eq "File") { "$zoneName.dns" } else { "N/A" }
                        Method = "dnscmd"
                        ErrorMessage = $null
                        Status = "Success"
                        CollectionTime = Get-Date
                    }

                    $zoneResults += $zoneObj
                } catch {
                    Write-Warning "Error parsing zone line: $zoneLine - $($_.Exception.Message)"
                }
            }
        }

        # Add forwarders using dnscmd if requested
        if ($IncludeForwarders) {
            try {
                $forwarderCmd = "dnscmd $ComputerName /info /forwarders"
                $forwarderOut = Invoke-Expression $forwarderCmd 2>$null

                if ($LASTEXITCODE -eq 0 -and $forwarderOut) {
                    $forwarderIPs = $forwarderOut | Where-Object { $_ -match "^\s*\d+\.\d+\.\d+\.\d+" } | ForEach-Object { $_.Trim() }

                    if ($forwarderIPs) {
                        $forwarderObj = [PSCustomObject]@{
                            Computer = $ComputerName
                            Name = "Forwarders"
                            ZoneType = "Forwarder"
                            Storage = "Config"
                            Properties = ($forwarderIPs -join ", ")
                            IsReverseLookup = $false
                            IsSigned = $false
                            DynamicUpdate = "None"
                            ZoneFile = "N/A"
                            Method = "dnscmd"
                            ErrorMessage = $null
                            Status = "Success"
                            CollectionTime = Get-Date
                        }
                        $zoneResults += $forwarderObj
                    }
                }
            } catch {
                Write-Warning "Could not retrieve forwarders using dnscmd: $($_.Exception.Message)"
            }
        }

        Write-Verbose "Successfully retrieved $($zoneResults.Count) zones using dnscmd from $ComputerName"

    } catch {
        Write-Warning "Failed to retrieve DNS zones from $ComputerName : $($_.Exception.Message)"

        # Return error object
        $zoneResults = @([PSCustomObject]@{
            Computer = $ComputerName
            Name = "ERROR"
            ZoneType = "N/A"
            Storage = "N/A"
            Properties = "N/A"
            IsReverseLookup = $false
            IsSigned = $false
            DynamicUpdate = "N/A"
            ZoneFile = "N/A"
            Method = "Failed"
            ErrorMessage = $_.Exception.Message
            Status = "Failed"
            CollectionTime = Get-Date
        })
    }

    return $zoneResults
}

function Export-DNSResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CSV', 'JSON', 'Excel', 'Object')]
        [string]$Format
    )

    if (-not $Data -or $Data.Count -eq 0) {
        Write-Warning "No data to export"
        return
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    switch ($Format) {
        'CSV' {
            $outputFile = Join-Path $OutputPath "$DomainName-DNSZones-v2.0-$timestamp.csv"
            $Data | Export-Csv -Path $outputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8
            Write-Host "DNS zone information exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'JSON' {
            $outputFile = Join-Path $OutputPath "$DomainName-DNSZones-v2.0-$timestamp.json"
            $Data | ConvertTo-Json -Depth 4 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "DNS zone information exported to: $outputFile" -ForegroundColor Green
            return $outputFile
        }

        'Excel' {
            try {
                $outputFile = Join-Path $OutputPath "$DomainName-DNSZones-v2.0-$timestamp.xlsx"

                # Try to use ImportExcel module if available
                if (Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue) {
                    Import-Module ImportExcel -ErrorAction Stop
                    $Data | Export-Excel -Path $outputFile -AutoSize -FreezeTopRow -BoldTopRow -WorksheetName "DNS Zones"
                    Write-Host "DNS zone information exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                } else {
                    Write-Warning "ImportExcel module not available. Exporting as CSV instead."
                    $outputFile = Join-Path $OutputPath "$DomainName-DNSZones-v2.0-$timestamp.csv"
                    $Data | Export-Csv -Path $outputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8
                    Write-Host "DNS zone information exported to: $outputFile" -ForegroundColor Green
                    return $outputFile
                }
            } catch {
                Write-Warning "Excel export failed: $($_.Exception.Message). Falling back to CSV."
                $outputFile = Join-Path $OutputPath "$DomainName-DNSZones-v2.0-$timestamp.csv"
                $Data | Export-Csv -Path $outputFile -NoTypeInformation -Delimiter ";" -Encoding UTF8
                Write-Host "DNS zone information exported to: $outputFile" -ForegroundColor Green
                return $outputFile
            }
        }

        'Object' {
            Write-Host "Returning $($Data.Count) DNS zone objects" -ForegroundColor Green
            return $Data
        }
    }
}

# Main execution
try {
    Write-Verbose "Starting DNS zone enumeration script v2.0"

    # Import ActiveDirectory module if not already loaded
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Verbose "ActiveDirectory module imported successfully"
    }

    # Get domain information
    if ([string]::IsNullOrEmpty($DomainName)) {
        $domain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
        $DomainName = $domain.Name
        Write-Verbose "Using current domain: $DomainName"
    } else {
        $domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
        Write-Verbose "Using specified domain: $DomainName"
    }

    # Get all domain controllers
    Write-Verbose "Retrieving domain controllers for domain: $DomainName"
    $DCs = Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop

    if (-not $DCs) {
        throw "No domain controllers found for domain: $DomainName"
    }

    Write-Host "Found $($DCs.Count) domain controllers in $DomainName" -ForegroundColor Green
    Write-Host "Enumerating DNS zones..." -ForegroundColor Cyan

    # Collect DNS zone information from all DCs
    $allZones = @()
    $dcCount = 0

    foreach ($DC in $DCs) {
        $dcCount++
        Write-Progress -Activity "Enumerating DNS zones" -Status "Processing DC: $($DC.Name)" -PercentComplete (($dcCount / $DCs.Count) * 100)
        Write-Host "Processing DC: $($DC.Name) ($dcCount of $($DCs.Count))" -ForegroundColor Cyan

        $dcZones = Get-DNSZoneInfo -ComputerName $DC.Name -Credential $Credential -IncludeForwarders:$IncludeForwarders -IncludeZoneDetails:$IncludeZoneDetails -UseModernDNS:$UseModernDNS -TimeoutSeconds $TimeoutSeconds
        $allZones += $dcZones

        $successfulZones = $dcZones | Where-Object { $_.Name -ne "ERROR" }
        if ($successfulZones.Count -gt 0) {
            Write-Host "  Successfully retrieved $($successfulZones.Count) zones from $($DC.Name)" -ForegroundColor Green
        } else {
            Write-Host "  Failed to enumerate zones from $($DC.Name)" -ForegroundColor Red
        }
    }

    Write-Progress -Activity "Enumerating DNS zones" -Completed

    if (-not $allZones -or ($allZones | Where-Object { $_.Name -ne "ERROR" }).Count -eq 0) {
        throw "No DNS zone information was retrieved from any domain controller"
    }

    # Export results
    $result = Export-DNSResults -Data $allZones -OutputPath $OutputPath -DomainName $DomainName -Format $OutputFormat

    # Display comprehensive summary statistics
    $successfulZones = $allZones | Where-Object { $_.Name -ne "ERROR" }
    $errorZones = $allZones | Where-Object { $_.Name -eq "ERROR" }

    Write-Host "`nDNS Zone Enumeration Summary (v2.0):" -ForegroundColor Yellow
    Write-Host "Total Zones Found: $($successfulZones.Count)" -ForegroundColor White
    Write-Host "DCs with Errors: $(($errorZones | Group-Object Computer).Count)" -ForegroundColor Red

    if ($successfulZones.Count -gt 0) {
        # Zone type distribution
        $zoneTypes = $successfulZones | Group-Object ZoneType | Sort-Object Count -Descending
        Write-Host "`nZone Type Distribution:" -ForegroundColor Yellow
        foreach ($type in $zoneTypes) {
            Write-Host "  $($type.Name): $($type.Count)" -ForegroundColor White
        }

        # Storage type distribution
        $storageTypes = $successfulZones | Group-Object Storage | Sort-Object Count -Descending
        Write-Host "`nStorage Type Distribution:" -ForegroundColor Yellow
        foreach ($storage in $storageTypes) {
            Write-Host "  $($storage.Name): $($storage.Count)" -ForegroundColor White
        }

        # Special zones
        $reverseLookupZones = $successfulZones | Where-Object { $_.IsReverseLookup -eq $true }
        $signedZones = $successfulZones | Where-Object { $_.IsSigned -eq $true }
        $dynamicZones = $successfulZones | Where-Object { $_.DynamicUpdate -ne "None" }

        Write-Host "`nSpecial Zone Statistics:" -ForegroundColor Yellow
        Write-Host "  Reverse Lookup Zones: $($reverseLookupZones.Count)" -ForegroundColor Cyan
        Write-Host "  DNSSEC Signed Zones: $($signedZones.Count)" -ForegroundColor Cyan
        Write-Host "  Dynamic Update Zones: $($dynamicZones.Count)" -ForegroundColor Cyan

        # Per-DC zone counts
        $dcZoneCounts = $successfulZones | Group-Object Computer | Sort-Object Count -Descending
        Write-Host "`nZones per Domain Controller:" -ForegroundColor Yellow
        foreach ($dcZone in $dcZoneCounts) {
            Write-Host "  $($dcZone.Name): $($dcZone.Count) zones" -ForegroundColor White
        }

        # Method distribution
        $methods = $successfulZones | Group-Object Method | Sort-Object Count -Descending
        Write-Host "`nCollection Method Distribution:" -ForegroundColor Yellow
        foreach ($method in $methods) {
            Write-Host "  $($method.Name): $($method.Count)" -ForegroundColor White
        }
    }

    if ($errorZones.Count -gt 0) {
        Write-Host "`nDCs with Enumeration Errors:" -ForegroundColor Red
        foreach ($errorZone in $errorZones) {
            Write-Host "  $($errorZone.Computer): $($errorZone.ErrorMessage)" -ForegroundColor Red
        }
    }

    if ($OutputFormat -eq 'Object') {
        return $result
    }

} catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}





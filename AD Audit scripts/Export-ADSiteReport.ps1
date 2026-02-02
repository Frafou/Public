<#
.SYNOPSIS
    Exports Active Directory site information to CSV report

.DESCRIPTION
    Generates detailed report of AD sites including locations, ISTG, subnets, servers and site links

.NOTES
    Name: Export-ADSiteReport.ps1
    Author: Francois Fournier
    Version: 1.0
    DateCreated: 2024-01-01
    Purpose/Change: Initial script development

.EXAMPLE
    .\Export-ADSiteReport.ps1
#>

$LogDate = Get-Date -Format yyyyMMdd-HHmmss
# Rest of the original code remains unchanged
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$ReportName = ($ScriptName).Replace('.ps1', '') + " - $((Get-ADDomain).name) - ADSiteInfo" + '-' + $LogDate + '.CSV'
$ReportFile = "$ScriptPath" + '\report\' + "$ReportName"


$ThisString = 'AD Site,Location,Site Option,Current ISTG,Subnets,Servers,In Site Links,Bridgehead Servers'
Add-Content "$ReportFile" $ThisString

$CurForestName = (Get-ADForest).name
$a = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $CurForestName)
[array]$ADSites = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($a).sites
ForEach ($Site in $ADSites) {
    $SiteName = $Site.Name
    $SiteLocation = $site.Location
    $SiteOptions = $Site.Options
    $SiteISTG = $Site.InterSiteTopologyGenerator

    [array] $SiteServers = $Site.Servers.Count
    [array] $SiteSubnets = $Site.Subnets.Count
    [array] $SiteLinks = $Site.SiteLinks.Count
    [array] $SiteBH = $Site.BridgeheadServers.Count

    $FinalVal = $SiteName + ',' + '"' + $SiteLocation + '"' + ',' + '"' + $SiteOptions + '"' + ',' + $SiteISTG + ',' + $SiteSubnets + ',' + $SiteServers + ',' + $SiteLinks + ',' + $SiteBH
    Add-Content "$ReportFile" $FinalVal
}
Write-Output "Report: $ReportFile"
Write-Output "SiteList: $ReportName"
".\report\$CurForestName-Sites-$LogDate.txt"

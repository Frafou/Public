<#
.SYNOPSIS
	GET Forest trust  Info

.DESCRIPTION
	GET Forest trust  Info

.PARAMETER DC
    server name of forest DC

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$scriptName.log


.Example
  Export-ForestTrustInfo.ps1 -DC DC1

.Example
  Export-ForestTrustInfo.ps1 -DC DC1,DC2

.Notes
    NAME:      	Export-ForestTrustInfo.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-08-14
    KEYWORDS:   Inheritance

    V1.0 Initial version

.link
Https://www.

#>
#Requires -Version 5.1
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1)]
	[string[]]$DC
)
$date = Get-Date -Format yyyyMMdd-hhmmss
if (! $DC) {
	Write-Output "DC: $DC"
	$DCs = Get-ADDomainController
}

foreach ($DC in $DCs) {
	Write-Host '--------------'
	Write-Host "Forest info:`n"
	Get-ADForest -Server $DC | Out-File .\report\$($dc.Forest)-$($dc.domain)-ForestTrustinfo-$date.txt

	Write-Host '---'
	Write-Host "Trust info:`n"
	Get-ADTrust -Filter * -Server $DC | Out-File .\report\$($dc.Forest)-$($dc.domain)-ForestTrustinfo-$date.txt -Append
}

<#
.SYNOPSIS
    Identifies orphaned domain controller objects in Active Directory Sites and Services.

.DESCRIPTION
    This script performs a comparison between domain controller objects in two locations:
    1. Server objects in the Sites container (Configuration partition)
    2. Active domain controllers in the Domain partition

    It identifies orphaned DCs by finding servers that exist in the Configuration partition
    but are no longer present in the Domain partition.

.OutputS
    - Console Output showing count of servers in both partitions
    - alldcs.txt: List of current domain controllers
    - allsvrs.txt: List of server objects from Sites and Services
    - Detailed list of orphaned DCs if found

.NOTES
    Requires:
    - Active Directory PowerShell module
    - Domain admin or equivalent permissions
    - Windows PowerShell 5.1 or later
#>

Import-Module activedirectory
$DomainName = (Get-ADDomain).DNSRoot
$d = "*$DomainName"
$cp = (Get-ADRootDSE).configurationNamingContext # getting configuration partition

Write-Output "`nLooking for orphaned domain controllers in the $DomainName domain'n"

$svrs = Get-ADObject -Filter { (ObjectClass -eq 'server') -and (dNSHostName -like $d) } -SearchBase "CN=Sites,$cp" | Select-Object name | Sort-Object name
$svrs_H = $svrs | Group-Object -Property name -AsHashTable -AsString -NoElement

$DCs = Get-ADDomainController -Filter * | Sort-Object name
$DCs_H = $DCs | Group-Object -Property name -AsHashTable -AsString -NoElement

$i = $svrs_H.keys | Measure-Object
$j = $DCS_H.keys | Measure-Object

$x = $i.count
$y = $j.count
$NumOrph = $x - $y

Write-Output "$x server object(s) were found in the configuration partition."
Write-Output "$y domain controller(s) were found in the domain partition."
Write-Output '===='
Write-Output "$NumOrph potentially orphaned domain controllers"

<# Write text copies of Servers and DCs #>
IF (!(Test-Path '.\Output')) {
    # create the directory if it doesn't exist
    New-Item -ItemType Directory -Path '.\Output'
}

Get-ADDomainController -Filter * | Select-Object name | Sort-Object name | Out-File '.\Output\alldcs.txt'

Get-ADObject -Filter { (ObjectClass -eq 'server') -and (dNSHostName -like $d) } -Properties * -SearchBase "CN=Sites,$cp" | Select-Object Name | Sort-Object Name | Out-File '.\Output\allsvrs.txt'

(Get-Content .\Output\alldcs.txt) | ForEach-Object { $_ -replace ' ', '' } | Set-Content .\Output\alldcs.txt
(Get-Content .\Output\allsvrs.txt) | ForEach-Object { $_ -replace ' ', '' } | Set-Content .\Output\allsvrs.txt

$compare = Compare-Object -ReferenceObject (Get-Content .\Output\allsvrs.txt) -DifferenceObject (Get-Content .\Output\alldcs.txt)

if ($compare) {
    Write-Output ''
    Write-Output 'Orphaned (found in config, but not domain)'
    $compare | Select-Object @{Name = 'Domain Controller'; Expression = { $_.inputobject } }
} Else {

    Write-Output "`nNo orphaned domain controllers were found"
}


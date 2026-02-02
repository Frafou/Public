Import-Module activedirectory

$domain = Get-ADDomain -Current LocalComputer
$DomainName = $domain.name
################ DO NOT MODIFY #############

$FRSsysvol = "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,"+(Get-ADDomain $domainName).DistinguishedName
$DFSRsysvol = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,"+(Get-ADDomain $domainName).DistinguishedName

$frs = Get-ADObject -Filter { distinguishedName -eq $FRSsysvol } -Server $DomainName
$dfsr = Get-ADObject -Filter { distinguishedName -eq $DFSRsysvol } -Server $DomainName


if ( $frs -ne $null ) { Write-Host -ForegroundColor red "FRS" }

elseif ( $dfsr -ne $null ) { Write-Host -ForegroundColor green "DFS-R" }

else { Write-Host -ForegroundColor Red "unknown" }

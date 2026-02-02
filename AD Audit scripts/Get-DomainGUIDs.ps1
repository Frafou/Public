$domains = (Get-ADForest -server $(Get-ADDomainController).name).Domains; foreach ($d in $domains) { Get-ADDomain -Identity $d | Select-Object Name, DNSRoot, ObjectGuid
}
$Domains

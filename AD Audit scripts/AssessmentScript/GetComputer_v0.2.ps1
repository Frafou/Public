Import-Module activedirectory

$domain = Get-ADDomain -Current LocalComputer
$DomainName = $domain.name
$OutFile = $domain.name + "-Computer.csv"

################ DO NOT MODIFY #############

Get-ADComputer -Filter * -server $domainname -Properties Name,Description,whenChanged,OperatingSystem, OperatingSystemVersion, PasswordLastSet, LastLogonDate | Export-Csv -Path $OutFile -NoTypeInformation 


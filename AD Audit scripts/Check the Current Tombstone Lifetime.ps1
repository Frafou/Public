#https://community.spiceworks.com/t/how-to-change-the-retention-period-in-ad-recycle-bin/1014138


Import-Module ActiveDirectory

$ADForestconfigurationNamingContext = (Get-ADRootDSE).configurationNamingContext

$DirectoryServicesConfigPartition = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ADForestconfigurationNamingContext" -Partition $ADForestconfigurationNamingContext -Properties *

$TombstoneLifetime = $DirectoryServicesConfigPartition.tombstoneLifetime

Write-Output "Active Directory's Tombstone Lifetime is set to $TombstoneLifetime days"



Break

$ADForestconfigurationNamingContext = (Get-ADRootDSE).configurationNamingContext

Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ADForestconfigurationNamingContext" -Partition $ADForestconfigurationNamingContext -Replace @{tombstonelifetime = '365' }

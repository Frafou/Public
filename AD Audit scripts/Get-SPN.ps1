Get-ADUser -Identity abi -Properties ServicePrincipalNames | Select-Object -ExpandProperty ServicePrincipalNames

# https://www.techcrafters.com/portal/en/kb/articles/how-to-list-all-spns-in-a-domain-using-powershell#Advanced_Techniques

#Querying SPNs
Get-ADUser -Filter 'ServicePrincipalNames -like "*"' -Properties ServicePrincipalNames

#Checking for Duplicate SPNs
Get-ADServiceAccount -Filter 'ServicePrincipalNames -like "*"' | ForEach-Object { $_.ServicePrincipalNames | Group-Object | Where-Object { $_.Count -gt 1 } }

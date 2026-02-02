
$adroot = [adsi]"GC://DC=raffinerie,DC=intranet"
$desSearch=[adsisearcher]"userAccountControl:1.2.840.113556.1.4.803:=2097152"
$desSearch.PageSize = 1000
$Output = $desSearch.FindAll() | Out-File -FilePath DESUsers.txt




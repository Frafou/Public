Write-Output 'Testing for users with PASSWD_NOTREQD:'
$noPwdRequired = Get-ADUser -LDAPFilter '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=544))'
Write-Output 'Users with PASSWD_NOTREQD:'
Write-Output $noPwdRequired


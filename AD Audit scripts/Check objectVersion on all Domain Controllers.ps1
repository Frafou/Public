$schemaContext = Get-ADRootDSE | ForEach-Object { $_.schemaNamingContext }

Foreach ($dc in ([System.DirectoryServices.ActiveDirectory.DomainController]::findall(
            (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $env:USERDNSDOMAIN)))) |
        ForEach-Object { $_.name }) {
    $path = 'LDAP://' + $dc + '/' + $schemaContext
    $Object = [adsi]$path
    $dc + ' ' + $Object.objectversion
}

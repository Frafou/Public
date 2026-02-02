$Group = 'G_BRP_AzureAD_License_O365_ProPlus'
$Group = 'G_BRP_AzureAD_License_M365_E3'


$Users = (Get-ADGroup $Group -Properties Member).Member | Get-ADUser -Properties * | Select-Object name, samaccountname, EmailAddress
$users | Export-Csv -Path .\$Group.csv -NoTypeInformation

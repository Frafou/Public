<#
Microsoft supported backups of Active Directory are very important to have. For backing up Domain Controllers, this is typically a System State backup.

Why a Microsoft supported backup?
If you are using a backup solution that isn't fully AD aware, performing a restore may involve getting Microsoft involved and that costs $$.

I know companies that have used ####### (redacted) to backup their AD and there was no System State and the backup wasn't a full AD aware backup so they ended up paying ###### $$$ and Microsoft $$$.

Just get a System State backup of the DCs that host your FSMO roles about every month and be prepared for a scenario where you may have to restore AD.

Determining if a recent supported backup has been performed is easy since these backups update a bit in each partition.

PowerShell code to check the current domain for the last Microsoft supported AD backup:
#>
$ContextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
$Context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($ContextType, (Get-ADDomain).DNSRoot)
$DomainController = [System.DirectoryServices.ActiveDirectory.DomainController]::findOne($Context)
[string[]]$Partitions = (Get-ADRootDSE).namingContexts

foreach ($Partition in $Partitions) {
	$dsaSignature = $DomainController.GetReplicationMetadata($Partition).Item('dsaSignature')
	Write-Host "$Partition was backed up $($dsaSignature.LastOriginatingChangeTime.DateTime)"
}

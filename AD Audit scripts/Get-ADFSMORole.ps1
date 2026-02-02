function Get-ADFSMORole {
    [CmdletBinding()]
    param()
    $ADDomain = Get-ADDomain | Select-Object InfrastructureMaster, PDCEmulator, RIDMaster
    $ADForest = Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
    $Output = @{
        InfrastructureMaster = $ADDomain.InfrastructureMaster
        PDCEmulator          = $ADDomain.PDCEmulator
        RIDMaster            = $ADDomain.RIDMaster
        DomainNamingMaster   = $ADForest.DomainNamingMaster
        SchemaMaster         = $ADForest.SchemaMaster
    }
    Write-Output $Output
}

Get-ADFSMORole

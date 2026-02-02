<#
.SYNOPSIS
	Outputs Expired Active Directory User information to a CSV file.

.DESCRIPTION
	Quieries Active directory for User information
.PARAMETER SearchBase
        "The searchbase between quotes or multiple separated with a comma"
.PARAMETER Path
	Specifies a path to csv file. Wildcards are not permitted. The default path is ADUsers-yyyy-MM-dd.csv

.INPUTS
	None

.OUTPUTS
	CSV:  .\Expired-ADUsers-yyyy-MM-dd.csv"

.Example
    Export-ExpiredAccounts.ps1 -verbose

.Notes
    NAME:       Export-ExpiredAccounts.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-02-13
#>

param(
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Enter the searchbase between quotes or multiple separated with a comma"
    )]
    [string[]]$searchBase,
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Enter path to save the CSV file"
    )]
    [string]$path = ".\Report\Expired-ADUsers-$((Get-Date -format "yyyy-MM-dd").ToString()).csv"
)

Function Get-AllADUsers {
    <#
    .SYNOPSIS
      Get all AD Users
  #>
    process {
        Write-Host "Collecting Users" -ForegroundColor Cyan
        # Collect Users
        if ($searchBase) {
            # Get the requested mailboxes
            foreach ($dn in $searchBase) {
                Write-Host "- Get Users in $dn" -ForegroundColor Cyan
                $Users = Get-ADUser -Filter $filter -searchBase $dn -Properties Samaccountname, name, Enabled, AccountExpirationDate, LastLogonDate | Where-Object { ($NULL -NE $_.AccountExpirationDate -AND $_.AccountExpirationDate -LT (Get-Date)) }
            }
        }
        else {
            # Get distinguishedName of the domain
            $dn = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
            Write-Host "- Get Users in $dn" -ForegroundColor Cyan
            $Users = Get-ADUser -Filter $filter -Properties Samaccountname, name, Enabled, AccountExpirationDate, LastLogonDate | Where-Object { ($NULL -NE $_.AccountExpirationDate -AND $_.AccountExpirationDate -LT (Get-Date)) }

        }
        return $Users
    }
}

$filter = "*"
Get-AllADUsers | Export-CSV -Path $path -NoTypeInformation
if ((Get-Item $path).Length -gt 0) {
    Write-Host "Report finished and saved in $path" -ForegroundColor Green
    # Open the CSV file
    Invoke-Item $path
}
else {
    Write-Host "Failed to create report" -ForegroundColor Red
}



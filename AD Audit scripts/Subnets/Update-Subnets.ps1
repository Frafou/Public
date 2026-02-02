<#
.SYNOPSIS
	Check for Subnets

.DESCRIPTION
	Check for missing subnets from input file

.PARAMETER Path
	Specifies a path to one or more file system directories. Wildcards are not permitted. The default path is the current directory (.).

.INPUTS
	 D:\Scripts\AD\Subnets\Subs_for_AD.csv

.OUTPUTS
	Log:  .\subnets_MMddyyyyHHmm.log

.Example
    Update-Subnet.ps1 -verbose

.Notes
    NAME:       Update-Subnet.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2023-10-25

 #Requires -Version 2.0
 #>

[CmdletBinding()]
param(

    [parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0, ParameterSetName = "Path")]
    $InputFile = ".\Subs_for_AD.csv"

)

Clear-Host
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$LogFileName = ".\subnets_$LogDate.log"
$csvSubnets = Import-Csv -Path  $InputFile
"Validate Subnets" | out-file -FilePath $LogFileName
"Date: $LogDate" | out-file -FilePath $LogFileName -Append
"--------------------------------------`n" | out-file -FilePath $LogFileName -Append
$ValidSubnets = 0
$InvalidSubnets = 0
foreach ($Subnet in $csvSubnets) {
    try { Get-ADReplicationSubnet  -Identity "$($Subnet.subnet)" -ErrorAction SilentlyContinue | Out-Null
        Write-Verbose "$($Subnet.subnet) exists"
        "$($Subnet.subnet) exists" | out-file -FilePath $LogFileName -Append
        #count Valid subnets
        $ValidSubnets++
    }
    Catch {
        Write-Verbose "$($Subnet.subnet) does not exists"
        "$($Subnet.subnet) does not exists" | out-file -FilePath $LogFileName -Append
        try { New-ADReplicationSubnet  -Name $subnet.subnet -Description $subnet.description -Site $subnet.City -location $subnet.City -whatif
            Write-Verbose "$($Subnet.subnet) does not exists"
            "$($Subnet.subnet) does not exists" | out-file -FilePath $LogFileName -Append
        }
        catch {
            write-error "$error[0]"
            $error[0] | out-file -FilePath $LogFileName -Append
        }
        #count Invalid subnets
        $InvalidSubnets++
    }
}


"`n--------------------------------------" | out-file -FilePath $LogFileName -Append
"Report" | out-file -FilePath $LogFileName -Append
"Valid Subnets: $ValidSubnets" | out-file -FilePath $LogFileName -Append
"Invalid Subnets: $InvalidSubnets" | out-file -FilePath $LogFileName -Append

break




# Get script Start Time (used to measure run time)
$startDTM = (Get-Date)

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = "$ScriptPath" + '\Report\' + "$CSVName"

$DCs = Get-ADDomainController -Filter * | Sort-Object $_.hostname
foreach ($DC in $DCs) {
 Write-Output "Name: $($DC.hostname)"
 Get-DnsServerScavenging -ComputerName $DC.hostname
}

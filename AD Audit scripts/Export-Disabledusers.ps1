
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$logFile = "$ScriptPath" + '\' + "$LogName"
$ReportName = ($ScriptName).Replace('.ps1', '') + " - $((Get-ADDomain).name) - ADSiteInfo" + '-' + $LogDate + '.CSV'
$ReportFile = "$ScriptPath" + '\report\' + "$ReportName"


Get-ADUser -Filter { (Enabled -eq $False) } -Properties * | Export-Csv "$ReportFile" -NoTypeInformation
Write-Output 'ReportFile saved to:'
Write-Output "$ReportFile"

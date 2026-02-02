$date = Get-Date -Format yyyyMMdd-HHmmss
# Start-Transcript -Path C:\Scripts\AD\Audit
#$Computers = Get-Content ".\Test-Computer-20241119 Servers with security limitations.txt"
#$computers = Get-ADComputer -Filter * -Properties *

$computers = Get-ADComputer -Filter 'Name -like "seis-dc*"' -Properties *

$report = @()
# add-computer info
foreach ($Computer in $Computers) {
	Write-Host "Computer: $Computer"
	# Loop through all computers
	$ConnectInfo = Test-NetConnection -ComputerName $Computer.NAME -InformationLevel 'Detailed'



	$info = [pscustomobject]@{
		'Name'                    = $Computer.Name
		'CanonicalName'           = $Computer.CanonicalName
		'OS'                      = $Computer.OperatingSystem
		'OS Version'              = $Computer.OperatingSystemVersion
		'Last Logon'              = ($Computer.lastLogonDate).ToString('yyyy-MM-dd_HH:mm:ss')
		'Last Logon timestamp'    = [DateTime]::FromFileTime($Computer.lastlogontimestamp).ToString('yyyy-MM-dd_HH:mm:ss')
		'PwdLastSet'              = [DateTime]::FromFileTime($Computer.PwdLastSet).ToString('yyyy-MM-dd_HH:mm:ss')
		'PasswordLastSet'         = ($Computer.PasswordLastSet).ToString('yyyy-MM-dd_HH:mm:ss')
		'Logon Count'             = $Computer.logonCount
		'Bad Logon Count'         = $Computer.BadLogonCount
		'IP Address'              = $Computer.IPv4Address
		'Enabled'                 = if ($Computer.Enabled) {
			'enabled'
		}
		else {
			'disabled'
		}
		'Date created'            = $Computer.whenCreated
		'ComputerName'            = $ConnectInfo.ComputerName
		'RemoteAddress'           = $ConnectInfo.RemoteAddress
		',PingSucceeded'          = $ConnectInfo.PingSucceeded
		'TcpTestSucceeded'        = $ConnectInfo.TcpTestSucceeded
		'InterfaceAlias '         = $ConnectInfo.InterfaceAlias
		'InterfaceIndex'          = $ConnectInfo.InterfaceIndex
		'InterfaceDescription '   = $ConnectInfo.InterfaceDescription
		'NetAdapter'              = $ConnectInfo.NetAdapter
		'NetRoute '               = $ConnectInfo.NetRoute
		'SourceAddress '          = $ConnectInfo.SourceAddress
		'NameResolutionSucceeded' = $ConnectInfo.NameResolutionSucceeded

	}
	$report += $Info
}
$Report | EXPORT-CSV ".\Test-Computer-$date.csv" -NoTypeInformation -Encoding UTF8 -UseCulture
# Stop-Transcript






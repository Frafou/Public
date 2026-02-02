RUN ALL THE SCRIPTS ON EACH DOMAIN OF THE FOREST


	GetDCConfiguration.vbs --> Run cscript .\GetDCConfiguration.vbs <domain DN: ex. "DC=contoso,DC=COM">
	GetDCsShare.ps1 -- Run "PowerShell.exe -ExecutionPolicy Bypass -File .\GetDCsShare.ps1"
	DNSZone.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File .\DNSZone.ps1"
	GetDCsHW.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File .\GetDCsHW.ps1"
	Time.txt --> Copy and run the command in the file
	ResolveIP.ps1 & IPList.txt --> Run this script after DNSZone.ps1 and on IPList insert the IP to resolve
	DFSorRFS_v0.2.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File DFSorRFS_v0.3.ps1"
	FSMO_v0.2.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File FSMO_v0.2.ps1"
	GetComputer_v0.2.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File GetComputer_v0.2.ps1"
	UtentiDES.ps1 --> "PowerShell.exe -ExecutionPolicy Bypass -File UtentiDES_v0.2.ps1"



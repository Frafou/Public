# Change ScheduledTask To gMSA


[CmdletBinding()]
param(
	[Parameter(Mandatory = $true)]
	[string] $gMSAname,
	[Parameter(Mandatory = $true)]
	[string] $Taskname

)

if (-not($gMSAname.EndsWith('$'))) {
	$gMSAname = $gMSAname + '$'
} # If no trailing $ character in gMSA name, add $ sign

# Test gMSA account and get scheduled task
try {

	Test-ADServiceAccount -Identity $gMSAname -ErrorAction Stop
	Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop

}

catch {
	Write-Warning $($_.Exception.Message); break
}

# Change user account to gMSA for scheduled task
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDNSDOMAIN\$gMSAname" -LogonType Password -RunLevel Highest
try {
	Set-ScheduledTask $TaskName -Principal $Principal -ErrorAction Stop
} catch {
	Write-Warning $($_.Exception.Message); break
}



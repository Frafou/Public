<#
.SYNOPSIS
	Get members of a group

.DESCRIPTION
	Export users in the specified group

.PARAMETER Megatech
    This parameter will set the DC value to BRPMegatech.local DC to manage that forest
		'CASWVDC01.brpmegatech.local' # DC for BM


.PARAMETER BRP
    This parameter will set the DC value to BRP.local DC to manage that forest
		'CAVLPDC01.brp.local'  # DC for BRP

.INPUTS
	CSV file with the following header and info
	email, sourcegroup, destinationgroup

.OUTPUTS
	Log:  $scriptPath\output\Export-ADGroupMember-yyyyMMdd-hhmmss.log

.Example
    Export-ADGroupMember.ps1

.Example
    Export-ADGroupMember.ps1 -megatech

.Notes
    NAME:       Export-ADGroupMember.ps1
    AUTHOR:     Francois Fournier
    Last Edit:  2024-07-26
    KEYWORDS:   O365 Licence


		V1	initial version
		V2	added -Megatech Param and server option to manage both forest.
				-Megatech Switch will set $DC to 'casWvdc01.brpmegatech.local' to manage BRPMegatech domain,
				otherwise 'CAVLPDC01.brp.local' will be used for BRP domain.
.link
Https://www.

 #Requires -Version 5.0
 #>
[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 0)]
	[string]$Name,
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1)]
	[switch]$Megatech,
	[parameter(ValueFromPipeline = $true, Mandatory = $false, Position = 1)]
	[switch]$BRP
)
#Region Functions
function Get-Values($formTitle, $textTitle) {
	[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
	[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

	$objForm = New-Object System.Windows.Forms.Form
	$objForm.Text = $formTitle
	$objForm.Size = New-Object System.Drawing.Size(400, 250)
	$objForm.StartPosition = 'CenterScreen'

	$objForm.KeyPreview = $True
	$objForm.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') {
				$x = $objTextBox.Text; $objForm.Close()
			} })
	$objForm.Add_KeyDown({ if ($_.KeyCode -eq 'Escape') {
				$objForm.Close()
			} })

	$OKButton = New-Object System.Windows.Forms.Button
	$OKButton.Location = New-Object System.Drawing.Size(75, 120)
	$OKButton.Size = New-Object System.Drawing.Size(75, 23)
	$OKButton.Text = 'OK'
	$OKButton.Add_Click({ $Script:userInput = $objTextBox.Text; $objForm.Close() })
	$objForm.Controls.Add($OKButton)

	$CANCELButton = New-Object System.Windows.Forms.Button
	$CANCELButton.Location = New-Object System.Drawing.Size(150, 120)
	$CANCELButton.Size = New-Object System.Drawing.Size(100, 23)
	$CANCELButton.Text = 'CANCEL'
	$CANCELButton.Add_Click({ $objForm.Close() })
	$objForm.Controls.Add($CANCELButton)

	$objLabel = New-Object System.Windows.Forms.Label
	$objLabel.Location = New-Object System.Drawing.Size(10, 20)
	$objLabel.Size = New-Object System.Drawing.Size(500, 30)
	$objLabel.Text = $textTitle
	$objForm.Controls.Add($objLabel)

	$objTextBox = New-Object System.Windows.Forms.TextBox
	$objTextBox.Location = New-Object System.Drawing.Size(10, 50)
	$objTextBox.Size = New-Object System.Drawing.Size(350, 20)
	$objForm.Controls.Add($objTextBox)

	$objForm.Topmost = $True

	$objForm.Add_Shown({ $objForm.Activate() })

	[void] $objForm.ShowDialog()

	return $userInput
}

function Select-Domain() {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing

	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'Domain Controler'
	$form.Size = New-Object System.Drawing.Size(500, 225)
	$form.StartPosition = 'CenterScreen'

	$okButton = New-Object System.Windows.Forms.Button
	$okButton.Location = New-Object System.Drawing.Point(75, 120)
	$okButton.Size = New-Object System.Drawing.Size(75, 23)
	$okButton.Text = 'OK'
	$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
	$form.AcceptButton = $okButton
	$form.Controls.Add($okButton)

	$cancelButton = New-Object System.Windows.Forms.Button
	$cancelButton.Location = New-Object System.Drawing.Point(150, 120)
	$cancelButton.Size = New-Object System.Drawing.Size(75, 23)
	$cancelButton.Text = 'Cancel'
	$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
	$form.CancelButton = $cancelButton
	$form.Controls.Add($cancelButton)

	$label = New-Object System.Windows.Forms.Label
	$label.Location = New-Object System.Drawing.Point(10, 20)
	$label.Size = New-Object System.Drawing.Size(280, 20)
	$label.Text = 'Please select a Domain Controler:'
	$form.Controls.Add($label)

	$listBox = New-Object System.Windows.Forms.ListBox
	$listBox.Location = New-Object System.Drawing.Point(10, 40)
	$listBox.Size = New-Object System.Drawing.Size(260, 20)
	$listBox.Height = 80

	[void] $listBox.Items.Add('cavlpdc01.brp.Local')
	[void] $listBox.Items.Add('caswvdc01.brpmegatech.local')

	$form.Controls.Add($listBox)

	$form.Topmost = $true

	$result = $form.ShowDialog()

	if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
		$x = $listBox.SelectedItem
		$x
	}
}

#Endregion Functions

<#
=====================================================
 Variables
=====================================================
#>

#Define location of my script variable
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$LogName = ($ScriptName).Replace(".ps1", "") + "-" + $LogDate + ".log"
$logFile = "$ScriptPath" + "\Logs\" + "$LogName"
$CSVName = ($ScriptName).Replace(".ps1", "") + "-" + $LogDate + ".csv"
$CSVFile = "$ScriptPath" + "\output\" + "$CSVName"

#--------------------
# Import Modules
#--------------------

Write-Host "Importing Logging Module"
if (Get-InstalledModule -Name "pslogging") {
	Import-module PSLogging
}
else {
	try {
		Write-Host "Logging Module not available" -ForegroundColor red

		Write-Host "Installing Logging Module"
		Install-module PSLogging
	}
	catch {
		Write-Error "Unable to install PSLogging Module"
		exit 1
	}
}

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion "1.5" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Starting script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "Importing Required modules" -ToScreen

Write-LogInfo -LogPath $logFile -Message "ActiveDirectory" -ToScreen
if (Get-Module -ListAvailable -Name "ActiveDirectory") {
	Write-Output "Importing Module ActiveDirectory"
	Import-module ActiveDirectory
}
else {
	Write-Error "ActiveDirectory Module required"
	Write-Error "Please install required components (RSAT)"
	exit 1
}
#--------------------
# Begin Process
#--------------------
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Starting Processing" -ToScreen
#Set WhatIfPreference
if ($Whatif) {
	$WhatIfPreferencePrevious = $WhatIfPreference
	Write-LogWarning -LogPath $logFile -Message "WhatIf Switch applied, setting WhatIf Preference to true" -ToScreen
	$WhatIfPreference = $true
}

#EndRegion Inputfile

if ( $Megatech -or $BRP) {

	if ($Megatech) {
		#---------- BRPMegatech ---------------------
		$DC = 'caswvdc01.brpmegatech.local'
	}
	If ($brp) {
		#---------- BRP -----------
		$DC = 'cavlpdc01.brp.Local'
	}

}
else {
	$DC = Select-Domain
}

Write-LogInfo -LogPath $logFile -Message "DC: $DC" -ToScreen
if ($Name) {
	$Groups = (Get-ADGroup -Filter "name -like '$Name*'" -Server $DC | Select-Object name | Out-GridView -OutputMode Multiple).name
}
else {
	$Name = Get-Values 'Group' 'Enter Group Filter'
	$Groups = (Get-ADGroup -Filter "name -like '$Name*'" -Server $DC | Select-Object name | Out-GridView -OutputMode Multiple).name
}

foreach ($Group in $Groups) {
	$Date = Get-Date -Format 'yyyy-MM-dd-HH-mm-ss'
	$CSVFile = "$ScriptPath" + "\output\" + "Export-ADGroupMember-$Group-$date.csv"
	Write-LogInfo -LogPath $logFile -Message "--------------------------------" -ToScreen
	Write-LogInfo -LogPath $logFile -Message "$Date" -ToScreen
	Write-LogInfo -LogPath $logFile -Message "Getting group info for: $Group" -ToScreen
	Get-ADGroup $Group -Properties * | Select-Object -Property SamAccountName, Name, Description, DistinguishedName, CanonicalName, GroupCategory, GroupScope, whenCreated
	Write-LogInfo -LogPath $logFile -Message "Getting users from group: $Group" -ToScreen
	$Users = (Get-ADGroup $Group -Server $DC -Properties member).member
	Write-LogInfo -LogPath $logFile -Message "User count: $($Users.count)" -ToScreen
	Write-LogInfo -LogPath $logFile -Message "Getting user information" -ToScreen
	$ADUsers = $Users | Get-ADUser -Server $DC -Property SamAccountName, Enabled | select-object DistinguishedName, Enabled, GivenName, Name, SamAccountName, Surname, UserPrincipalName

	Write-LogInfo -LogPath $logFile -Message "Exporting user information to $CSVFile" -ToScreen
	$ADUsers | Sort-Object -Property Enabled, SamAccountName | Export-Csv "$CSVFile" -NoTypeInformation

	#---------- Disabled users
	Write-LogInfo -LogPath $logFile -Message "Check for disabled users" -ToScreen
	$DisabledUsers = $ADUsers | Where-Object { $_.Enabled -like 'false' }

	if ($DisabledUsers) {
		$CSVFile = "$ScriptPath" + "\output\" + "Export-ADGroupMember-$Group-$date-DisabledUsers.csv"
		$DisabledUsersCount =  ($DisabledUsers | Measure-Object).Count
		Write-LogInfo -LogPath $logFile -Message "`tDisabled User count: $DisabledUsersCount" -ToScreen
		Write-LogInfo -LogPath $logFile -Message "`tExporting disabled user information" -ToScreen
		$DisabledUsers | Export-Csv "$CSVFile" -NoTypeInformation
		Write-LogInfo -LogPath $logFile -Message "`tDisabled users exported to: $CSVFile" -ToScreen
 }
	else {
		Write-LogInfo -LogPath $logFile -Message "`tNo disabled User found" -ToScreen
 }
}

#-----------
#Finish
#-----------
if ($Whatif) {
	#reset $WhatifPreference
	Write-Host "Reverting WhatIf Preference to previous value" -ForegroundColor red
	$WhatIfPreference = $WhatifPreferencePrevious
}
Write-LogInfo -LogPath $logFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $logFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $logFile -Message "DataFile : $CSVFile" -ToScreen
Write-LogInfo -LogPath $logFile -Message "Logfile : $logFile" -ToScreen
Stop-Log -LogPath $logFile -ToScreen -NoExit
#SCRIPT ENDS


<#
.SYNOPSIS
    This PowerShell script re-encodes non-HEVC video files in a specified directory and its subdirectories using x265 HEVC video codec with a medium preset and 23 quality.

.DESCRIPTION
    The PowerShell script scans a directory and its subdirectories for non-HEVC video files, renames them and converts any MP4 files to MKV, then re-encodes the videos using the x265 HEVC codec and a medium preset with a 23 quality.

.PARAMETER LogOnly
    Boolean switch for LogOnly

.PARAMETER InputPath
    Literal path to Source files to convert

.PARAMETER ffmpegPath
    Literal path to FFMpeg.exe file

.PARAMETER ffprobePath
    Literal path to FFprobe.exe file

.INPUTS
	.none

.OUTPUTS
	Log:  $scriptPath\$LogName.log
	# This code creates a log file with a unique timestamp in the specified directory.

.OUTPUTS
	Data:  $scriptPath\$scriptName.csv

.Example
  StreamShift.ps1

.Example
  StreamShift.ps1 -LogOnly

	.Example
  StreamShift.ps1 -inputPath '\\pvr\Series\Star Trek\Discovery'

.Example
    StreamShift.ps1 -inputPath '\\pvr\Series\Star Trek\Discovery' -ffmpegPath 'C:\Program Files\ffmpeg\bin\ffmpeg.exe' -ffprobePath 'C:\Program Files\ffmpeg\bin\ffprobe.exe' -LogOnly

.Notes
    NAME:       StreamShift.ps1
    AUTHOR:     Oracle (Emby)
    Date:       2023-04-20
    LAST EDIT:  2025-03-22
    KEYWORDS:   Video Encoding, HEVC, x265, ffmpeg, ffprobe, PowerShell
		VERSION:    1.0.8

    V1.0.0 Initial version
    V1.0.1 - Modified the script to reference the locations of FFmpeg and FFprobe using a variable, instead of directly calling them.
    V1.0.2 - Adjusted the color of the console output was modified to improve its readability.
    V1.0.3 - Implemented functionality to re-encode .AVI files and convert them into .MKV files.
    V1.0.4 - Resolved problems related to renaming .AVI files to .MKV format.
    V1.0.5 - Improved file organization by changing names of output and tool directories.
    V1.0.6 - Resolved problem with invoking executables using variables.
    V1.0.7 - Changed FFprobe to exclude 720p format and renamed output file.
    V1.0.8 - Added PSLogging for more effective login, added Switch for Logging only, and added some file/Stream info to the output.


.link
https://emby.media/community/index.php?/topic/118164-x265-or-hevc-which-is-besteasiest/

https://ffbinaries.com/

https://trac.ffmpeg.org/wiki/Encode/H.264

Preset
A preset is a collection of options that will provide a certain encoding speed to compression ratio. A slower preset will provide better compression (compression is quality per file size). This means that, for example, if you target a certain file size or constant bit rate, you will achieve better quality with a slower preset. Similarly, for constant quality encoding, you will simply save bitrate by choosing a slower preset.

Use the slowest preset that you have patience for. The available presets in descending order of speed are:
	ultrafast
	superfast
	veryfast
	faster
	fast
	medium – default preset
	slow
	slower
	veryslow
	placebo – ignore this as it is not useful (see FAQ)

You can see a list of current presets with -preset help (see example below). If you have the x264 binary installed, you can also see the exact settings these presets apply by running x264 --fullhelp.
#>
#Requires -Version 5

[CmdletBinding()]
param(
	[parameter(ValueFromPipeline = $true, Mandatory = $false)]
	[String]$inputPath = '\\server\share\video',
	[parameter(ValueFromPipeline = $true, Mandatory = $false)]
	[String]$ffmpegPath = '.\ffmpeg.exe',
	[parameter(ValueFromPipeline = $true, Mandatory = $false)]
	[String]$ffprobePath = '.\ffprobe.exe',
	[parameter(ValueFromPipeline = $true, Mandatory = $false)]
	[switch]$LogOnly
)

#Define location of my script variable
$versionNumber = '1.0.9'
$ScriptName = Split-Path -Path $MyInvocation.MyCommand.Definition -Leaf
$ScriptPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
Set-Location $ScriptPath
$LogDate = Get-Date -Format yyyyMMdd-HHmmss
$logPath = "$ScriptPath" + '\Logs\'
$LogName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.log'
$LogFile = $logPath + "$LogName"
$CSVPath = "$ScriptPath" + '\Output\'
$CSVName = ($ScriptName).Replace('.ps1', '') + '-' + $LogDate + '.csv'
$CSVFile = $CSVPath + "$CSVName"

# This code sets directories for video encoding and tool paths.
# $ffmpegPath = "$ScriptPath\ffmpeg.exe"
# $ffprobePath = "$ScriptPath\ffprobe.exe"
Write-Verbose '======================='
Write-Verbose "InformationPreference: $InformationPreference"
Write-Verbose "VerbosePreference:$VerbosePreference"
Write-Verbose "ScriptPath: $ScriptPath"
Write-Verbose "LogFile:	$LogFile"
Write-Verbose "DataFile:	$CSVFile"
Write-Verbose "ffmpegPath:	$ffmpegPath"
Write-Verbose "ffprobePath:	$ffprobePath"
Write-Verbose "=======================`n"
#EndRegion Variables


if (-not (Test-Path $logPath -PathType Container)) {
	try {
		New-Item -Path $logPath -ItemType Directory | Out-Null
		Write-Host 'Log Path Created'
	} catch {
		<#Do this if a terminating exception happens#>
		Write-Error 'Unable to create log file'
		Break
	}
}
if (-not (Test-Path $CSVPath -PathType Container)) {
	try {
		New-Item -Path $CSVPath -ItemType Directory | Out-Null
		Write-Host 'Log Path Created'
	} catch {
		<#Do this if a terminating exception happens#>
		Write-Error 'Unable to create log file'
		Break
	}
}


#Region Module PSLogging
#--------------------
# Import PSLogging Module
#--------------------

Write-Host 'Importing Logging Module'
if (Get-InstalledModule -Name 'PSLogging') {
	Import-Module PSLogging
} else {
	try {
		Write-Host 'Logging Module not available' -ForegroundColor red

		Write-Host 'Installing Logging Module'
		Install-Module PSLogging -Scope AllUsers -Force -AllowClobber
	} catch {
		Write-Error 'Unable to install PSLogging Module'
		exit 1
	}
}
#EndRegion Module PSLogging

#--------------------
# Start Logging
#--------------------

Start-Log -LogPath $LogPath -LogName $LogName -ScriptVersion $versionNumber -ToScreen
Write-LogInfo -LogPath $LogFile -Message "Starting script.`n" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tServer: $env:computername" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tScriptPath: $ScriptPath" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`tScriptName: $ScriptName" -ToScreen

#Region Process
#--------------------
# Start Processing
#--------------------
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message 'Starting Processing' -ToScreen
#-------------------
# Begin Process
#--------------------


# This code adds version information, log ID, and source/destination directories to the log output.
Write-LogInfo -LogPath $LogFile -Message '[INFO] The PowerShell script scans a directory and its subdirectories for non-HEVC 720p video files, renames them and converts any MP4 files to MKV, then re-encodes the videos using the x265 HEVC codec and a medium preset with a 23 quality.' -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`n[INFO] Script Version: $versionNumber" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`n[INFO] Log: $logName" -ToScreen

# This code retrieves a list of all .mp4 and .mkv video files in a directory and its subdirectories.
$videoList = Get-ChildItem -Path $inputPath -Recurse -Include *.mp4, *.mkv, *.avi -File -Verbose
$videoList | Export-Csv $CSVFile -NoTypeInformation
# This code iterates over a list of video files, retrieves their details using ffprobe, and converts the output to JSON format.

if ($LogOnly) {
	Write-LogInfo -LogPath $LogFile -Message "`nLog Only selected, conversion of file will not be executed" -ToScreen
}

foreach ($videoFile in $videoList) {
	$StartTime = Get-Date
	Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
	Write-LogInfo -LogPath $LogFile -Message "VideoFile FullName: $($videoFile.FullName)" -ToScreen
	$videoDetails = & $ffprobePath -v error -show_streams -of json $videoFile.FullName | ConvertFrom-Json

	# This code checks if a video stream is HEVC encoded.
	$IsHEVC = $false
	foreach ($videoStream in $videoDetails.streams) {
		Write-LogInfo -LogPath $LogFile -Message "`n`tStream Index: $($videoStream.index)" -ToScreen
		Write-LogInfo -LogPath $LogFile -Message "`tCodec_name: $($videoStream.codec_name)" -ToScreen
		Write-LogInfo -LogPath $LogFile -Message "`tWidth: $($videoStream.width)" -ToScreen
		Write-LogInfo -LogPath $LogFile -Message "`tHeight: $($videoStream.height)" -ToScreen

		if ($videoStream.codec_type -eq 'video' -and $videoStream.codec_name -eq 'hevc') {

			$IsHEVC = $true
			Write-LogInfo -LogPath $LogFile -Message "`tHEVC Stream Found" -ToScreen
			break

		} else {
			<# Action when all if and elseif conditions are false #>
			Write-LogInfo -LogPath $LogFile -Message "`tHEVC Stream not Found" -ToScreen
		}
	}
	Write-LogInfo -LogPath $LogFile -Message "`nHEVC: $IsHEVC" -ToScreen
	# This code renames non-HEVC videos with _converted suffix and optionally converts mp4 to mkv.
	if (-not $LogOnly) {
		if (!$IsHEVC) {
			Write-LogInfo -LogPath $LogFile -Message "`nConverting file" -ToScreen
			Write-LogInfo -LogPath $LogFile -Message 'Renaming Original file' -ToScreen
			$outputFile = Join-Path $videoFile.Directory $videoFile.Name.Replace($videoFile.Extension, '_converted.mkv')
			if ($videoFile.Extension -eq '.mp4') {
				Write-LogInfo -LogPath $LogFile -Message 'Renaming MP4 file to MKV' -ToScreen
				$outputFile = $outputFile.Replace('.mp4', '.mkv')
			} elseif ($videoFile.Extension -eq '.avi') {
				Write-LogInfo -LogPath $LogFile -Message 'Renaming MP4 file to MKV' -ToScreen
				$outputFile = $outputFile.Replace('.avi', '.mkv')
			}

			# This code uses x265 to re-encode a video and displays a message after completion.
			Write-LogInfo -LogPath $LogFile -Message 'Re-encoding file' -ToScreen
			& $ffmpegPath -i $videoFile.FullName -c:v libx265 -preset slow -crf 23 -c:a copy $outputFile
			Write-LogInfo -LogPath $LogFile -Message "[INFO] $($videoFile.FullName) has been re-encoded as $($outputFile)" -ToScreen
		} else {
			<# Action when all if and elseif conditions are false #>
			Write-LogInfo -LogPath $LogFile -Message 'Conversion skipped' -ToScreen
		}
	}
	$EndTime = Get-Date
	$timeDifference = $EndTime - $Starttime
	Write-LogInfo -LogPath $LogFile -Message "Processing Time: $($timeDifference.Hours) hours, $($timeDifference.Minutes) minutes, and $($timeDifference.Seconds) seconds. " -ToScreen

}

# This code stops transcript logging, clears the console, displays a message, and waits for user input before exiting the script.

Write-LogInfo -LogPath $LogFile -Message "$scriptName $versionNumber has finished running at $([string]::Format('{0:MM-dd-yyyy HH:mm:ss}', [datetime]::Now)).`n`nView the log file $logName in $logPath for full details." -ToScreen
#Read-Host "`nPress [⏎] to exit the script."
#-----------
#End Processing
#-----------
#EndRegion Process

#Region Finish Script
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message "ReportFile:	$ReportFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "DataFile:		$CSVFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "LogFile:		$LogFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "ReportFile:	$ReportFile" -ToScreen

Stop-Log -LogPath $LogFile -ToScreen -NoExit

#EndRegion Finish Script

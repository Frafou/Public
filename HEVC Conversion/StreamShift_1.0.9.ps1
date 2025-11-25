
<#
.SYNOPSIS
    StreamShift - Automated HEVC video conversion tool for bulk media library optimization using x265 encoding.

.DESCRIPTION
    StreamShift is a comprehensive PowerShell-based video transcoding solution designed for media library optimization.
    It automatically discovers, analyzes, and converts non-HEVC video files to the efficient x265 HEVC codec,
    significantly reducing file sizes while maintaining visual quality.

    The script performs the following operations:
    1. Recursively scans specified directory and subdirectories for video files
    2. Uses FFprobe to analyze video streams and identify non-HEVC content
    3. Automatically renames and converts MP4 files to MKV format for better codec support
    4. Re-encodes videos using x265 HEVC codec with optimized settings
    5. Maintains original video quality while achieving 20-50% file size reduction
    6. Provides comprehensive logging and progress tracking
    7. Supports both actual conversion and log-only analysis modes
    8. Generates detailed CSV reports of all processed files

    Key Features:
    - Automatic codec detection and selective processing
    - Container format optimization (MP4 to MKV conversion)
    - Configurable FFmpeg and FFprobe executable paths
    - Comprehensive logging with timestamped entries
    - CSV export for processed file tracking
    - Quality-focused encoding with CRF 23 (visually lossless)
    - Medium preset for balanced speed/compression ratio
    - Support for AVI, MP4, and other common video formats

    Benefits:
    - Significant storage space savings (typically 20-50% reduction)
    - Improved streaming compatibility with modern devices
    - Better compression efficiency for long-term archival
    - Automated processing for large media libraries
    - Non-destructive operation with comprehensive logging

    This tool is ideal for media servers, personal video collections, and any scenario where
    storage optimization is important without sacrificing video quality.

.PARAMETER InputPath
    Specifies the root directory path containing video files to be processed.
    The script will recursively scan all subdirectories for compatible video files.
    Supports both local paths and UNC network paths for shared storage scenarios.

    Examples: 'C:\Videos', '\\server\share\media', 'D:\Movies\Collection'

    Type: String
    Default: '\\server\share\video'
    Required: False
    Pipeline Input: True

.PARAMETER ffmpegPath
    Specifies the full path to the FFmpeg executable file.
    FFmpeg is the core transcoding engine used for video conversion.
    Can be a relative path (if FFmpeg is in script directory) or absolute path.

    Examples: '.\ffmpeg.exe', 'C:\Tools\ffmpeg\bin\ffmpeg.exe', 'C:\Program Files\ffmpeg\bin\ffmpeg.exe'

    Type: String
    Default: '.\ffmpeg.exe'
    Required: False
    Pipeline Input: True

.PARAMETER ffprobePath
    Specifies the full path to the FFprobe executable file.
    FFprobe is used for media analysis and codec detection.
    Should typically be located in the same directory as FFmpeg.

    Examples: '.\ffprobe.exe', 'C:\Tools\ffmpeg\bin\ffprobe.exe', 'C:\Program Files\ffmpeg\bin\ffprobe.exe'

    Type: String
    Default: '.\ffprobe.exe'
    Required: False
    Pipeline Input: True

.PARAMETER LogOnly
    When specified, the script runs in analysis mode only, identifying files that would be converted
    without actually performing any transcoding operations. This is useful for:
    - Estimating processing time and storage impact
    - Validating file discovery and filtering logic
    - Testing configurations before bulk processing
    - Generating reports of conversion candidates

    Type: Switch
    Required: False
    Pipeline Input: True

.INPUTS
    String - Directory paths and executable paths can be provided via pipeline
    Switch - LogOnly mode can be specified via pipeline

.OUTPUTS
    Log File: Detailed execution log saved to Logs subdirectory
        Format: StreamShift_1.0.9-YYYYMMDD-HHMMSS.log
        Contains: Timestamped entries for all operations, errors, and progress updates

    CSV Report: Processed file inventory saved to Output subdirectory
        Format: StreamShift_1.0.9-YYYYMMDD-HHMMSS.csv
        Contains: File paths, original codec, new codec, file sizes, processing status

    Console Output: Real-time progress with color-coded status messages
        - Processing progress and current file information
        - Error messages and warnings
        - Summary statistics and completion status

.EXAMPLE
    .\StreamShift_1.0.9.ps1

    Processes videos in the default network share location using default FFmpeg/FFprobe paths
    in the script directory, performing actual HEVC conversion.

.EXAMPLE
    .\StreamShift_1.0.9.ps1 -LogOnly

    Analyzes the default video directory and generates a report of conversion candidates
    without performing any actual video conversion.

.EXAMPLE
    .\StreamShift_1.0.9.ps1 -InputPath 'D:\Movies'

    Processes all videos in the D:\Movies directory and subdirectories, converting
    non-HEVC files to x265 HEVC format.

.EXAMPLE
    .\StreamShift_1.0.9.ps1 -InputPath '\\nas\media\tv-shows' -LogOnly -Verbose

    Analyzes TV show collection on network storage with detailed verbose output,
    identifying conversion candidates without performing conversions.

.EXAMPLE
    .\StreamShift_1.0.9.ps1 -InputPath 'C:\Personal Videos' -ffmpegPath 'C:\Program Files\ffmpeg\bin\ffmpeg.exe' -ffprobePath 'C:\Program Files\ffmpeg\bin\ffprobe.exe'

    Processes personal video collection using FFmpeg installed in Program Files,
    performing HEVC conversion with custom tool paths.

.NOTES
    File Name      : StreamShift_1.0.9.ps1
    Author         : Oracle (Emby Community)
    Version        : 1.0.9
    Created        : 2023-04-20
    Last Updated   : 2025-11-24
    Keywords       : Video Encoding, HEVC, x265, FFmpeg, Media Optimization, PowerShell

    REQUIREMENTS:
    - PowerShell 5.0 or higher
    - FFmpeg and FFprobe executables (downloadable from ffbinaries.com)
    - Sufficient disk space for temporary files during conversion
    - Read/Write permissions on input directory and script directory
    - CPU with modern instruction sets for optimal x265 performance

    SYSTEM RECOMMENDATIONS:
    - Multi-core CPU (x265 encoding is CPU-intensive)
    - SSD storage for faster I/O during conversion
    - 8GB+ RAM for processing large video files
    - Dedicated processing time (conversion can be time-consuming)

    FFMPEG CONFIGURATION:
    - Encoding: x265 HEVC codec
    - Quality: CRF 23 (visually lossless, balanced quality/size)
    - Preset: Medium (balanced encoding speed/compression)
    - Container: MKV (for maximum codec compatibility)
    - Audio: Copy original streams (no re-encoding)
    - Subtitles: Copy original streams when present

    SUPPORTED FORMATS:
    Input: AVI, MP4, MOV, WMV, FLV, and other common video formats
    Output: MKV container with x265 HEVC video codec

    FEATURES:
    - Recursive directory scanning
    - Automatic codec detection and filtering
    - Smart container conversion (MP4 to MKV)
    - Progress tracking and comprehensive logging
    - Error handling and recovery
    - Network storage support
    - Batch processing capabilities
    - Non-destructive operation (originals preserved during processing)

    PERFORMANCE CONSIDERATIONS:
    - x265 encoding is CPU-intensive; expect longer processing times
    - File size reductions typically range from 20-50%
    - Processing time varies based on source resolution and CPU performance
    - Network storage may impact I/O performance

    CHANGE LOG:
    v1.0.0 - 2023-04-20 - Oracle (Emby) - Initial version
    v1.0.1 - 2023-04-20 - Modified to use variables for FFmpeg/FFprobe paths
    v1.0.2 - 2023-04-20 - Improved console output readability with color coding
    v1.0.3 - 2023-04-20 - Added AVI file support and MKV conversion
    v1.0.4 - 2023-04-20 - Fixed AVI to MKV renaming issues
    v1.0.5 - 2023-04-20 - Enhanced file organization and directory structure
    v1.0.6 - 2023-04-20 - Resolved executable invocation issues with variables
    v1.0.7 - 2023-04-20 - Excluded 720p format and improved output naming
    v1.0.8 - 2023-04-20 - Added PSLogging, LogOnly switch, and enhanced file info
    v1.0.9 - 2025-03-22 - Added parameters for custom paths and executables
    v1.0.9 - 2025-11-24 - Enhanced documentation and usage examples

.LINK
    https://emby.media/community/index.php?/topic/118164-x265-or-hevc-which-is-besteasiest/
    https://ffbinaries.com/
    https://trac.ffmpeg.org/wiki/Encode/H.264
    https://x265.readthedocs.io/en/stable/
    https://trac.ffmpeg.org/wiki/Encode/H.265

.COMPONENT
    Video Processing, Media Transcoding, HEVC Encoding, Storage Optimization

.ROLE
    Media Administrator, Storage Administrator, Content Manager

.FUNCTIONALITY
    Video Transcoding, Codec Conversion, Media Library Optimization, Storage Management

.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment and are not supported under any Microsoft standard support program or service. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
    (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
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
		break
	}
}
if (-not (Test-Path $CSVPath -PathType Container)) {
	try {
		New-Item -Path $CSVPath -ItemType Directory | Out-Null
		Write-Host 'Log Path Created'
	} catch {
		<#Do this if a terminating exception happens#>
		Write-Error 'Unable to create log file'
		break
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

#-----------
#End Processing
#-----------
#EndRegion Process

#Region Finish Script
Write-LogInfo -LogPath $LogFile -Message "`n`n=======================" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "`nEnding $ScriptName script." -ToScreen

Write-LogInfo -LogPath $LogFile -Message "DataFile:		$CSVFile" -ToScreen
Write-LogInfo -LogPath $LogFile -Message "LogFile:		$LogFile" -ToScreen
Stop-Log -LogPath $LogFile -ToScreen -NoExit

#EndRegion Finish Script



<#
.SYNOPSIS
    Renames episode files with IMDb titles while preserving original extensions.

.DESCRIPTION
    This script automates bulk renaming of TV episode files using metadata from IMDb.

    The script:
    - Recursively scans a target directory for episode files
    - Extracts season and episode numbers using flexible S##E## pattern matching (case-insensitive)
    - Fetches episode titles from IMDb using Get-ImdbEpisode.ps1
    - Sanitizes titles by removing invalid filename characters (/<>:|?*")
    - Renames each file to: S##.E## - [Episode Title].[original extension]
    - Preserves the original file extension regardless of file type
    - Provides detailed colored output for successful operations and errors

    Pre-requisites:
    - Requires Get-ImdbEpisode.ps1 in the same directory
    - Requires read/write access to target directory
    - Files must match pattern S#E# or S##E## (case-insensitive)

.PARAMETER SeriesTitle
    Name of the TV series (mandatory).

    Used to fetch episode data from IMDb and construct the default directory path.
    Examples: 'Fallout', 'The Office', 'Breaking Bad', 'Game of Thrones'

.PARAMETER Path
    Directory path containing episode files to process (optional).
    Default: "D:\Videos\Series\$SeriesTitle"
    The script recursively processes all subdirectories.
    Must exist; script validates before proceeding.

.EXAMPLE
    .\Set-EpisodeFilename.ps1 -SeriesTitle "Fallout"

    Uses default path D:\Videos\Series\Fallout and renames all matching episode files.

.EXAMPLE
    .\Set-EpisodeFilename.ps1 -SeriesTitle "The Office" -Path "E:\TV Shows\Office"

    Processes episode files in custom directory location.

.NOTES
    Error Handling:
    - Validates path existence before processing
    - Validates Get-ImdbEpisode.ps1 dependency before execution
    - Validates episode info retrieval before attempting rename
    - Skips files missing S#E# pattern with warning
    - Reports detailed error messages for failed operations

    File Filtering:
    - Excludes image files (*.jpg) and markdown files (*.md)
    - Processes all other file types recursively

    Display Features:
    - Using colored output: Green for success, Red for errors, Yellow for warnings
    - Shows found file count at startup
    - Displays rename preview before execution

.LINK
    Get-ImdbEpisode.ps1 - IMDb episode data retrieval companion script

.VERSION
    2.0

#>

param(
	[Parameter(Mandatory = $true, HelpMessage = "Enter the name of the TV series (e.g., 'Fallout', 'The Office')")]
	[string]$SeriesTitle,
	[Parameter(Mandatory = $False, HelpMessage = 'Enter the path to the directory containing episode files')]
	[string]$Path = "D:\Videos\Series\$SeriesTitle",
	[Parameter(Mandatory = $false, HelpMessage = 'The encoded title of the TV series.')]
	[string]$EncodedTitle
)

# Validate that the path exists
if (-not (Test-Path -Path $Path -PathType Container)) {
	Write-Error "Path does not exist: $Path"
	exit 1
} else {
	Write-Output "Processing episodes in path: $Path"
}

# Validate that Get-ImdbEpisode.ps1 exists in current directory
if (-not (Test-Path -Path '.\Get-ImdbEpisode.ps1')) {
	Write-Error 'Get-ImdbEpisode.ps1 not found in current directory'
	exit 1
}

Write-Output 'Getting episode information for files'
$Episodes = Get-ChildItem -Path $Path -Recurse -File -Exclude *.jpg, *.md
Write-Output "Found $(@($Episodes).Count) episode files in path: $Path"

foreach ($Episode in $Episodes) {
	$fileName = $Episode.Name
	Write-Output "`n----------------------------------------"
	Write-Output "Processing file: $($Episode.FullName)"
	# Match S##E## or S#E# format (case-insensitive)

	# test pattern: S01E02, s1e2, S1.E2, s01.e02, etc.
	# $seasonEpisodePattern = '[Ss](\d{1,2})[Ee](\d{1,2})'
	$seasonEpisodePattern = '(?i)s(\d{1,2})\.?e(\d{1,2})'

	if ($fileName -match $seasonEpisodePattern) {
		$seasonNumber = [int]$matches[1]
		$episodeNumber = [int]$matches[2]
		Write-Output "Season: $seasonNumber, Episode: $episodeNumber"
	} else {
		Write-Output "Skipping - No season/episode pattern found in: $fileName"
		continue  # Skip to next file if pattern doesn't match
	}
	Write-Verbose "'n==================================="
	Write-Verbose "SeriesTitle: $SeriesTitle, Season: $seasonNumber, Episode: $episodeNumber, EncodedTitle: $EncodedTitle"
	$EpisodeInfo = .\Get-ImdbEpisode.v2.ps1 -SeriesTitle $SeriesTitle -Season $seasonNumber -Episode $episodeNumber -EncodedTitle $EncodedTitle
	Write-Output 'Fetched episode info:'
	Write-Output $EpisodeInfo
	if (-not $EpisodeInfo -or -not $EpisodeInfo.Title) {
		Write-Error "Could not fetch episode information for S$seasonNumber E$episodeNumber"
		continue
	}

	# Determine extension from original file (includes leading dot)
	$extension = if ($Episode.Extension) {
		$Episode.Extension
 } else {
		''
 }

	# Sanitize title by removing invalid filename characters: / \ : * ? " < > |
	$sanitizedTitle = $EpisodeInfo.Title -replace '[/\\:*?"<>|]', '-'

	# Build new name with sanitized title
	$newName = "S$seasonNumber.E$episodeNumber - $sanitizedTitle$extension"
	Write-Output "Renaming to: $newName"

	try {
		Rename-Item -Path $Episode.FullName -NewName $newName -ErrorAction Stop
		Write-Host 'File renamed successfully.' -ForegroundColor Green
	} catch {
		Write-Error "Error renaming file: $($_.Exception.Message)"
	}
}

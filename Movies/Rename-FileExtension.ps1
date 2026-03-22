<#
.SYNOPSIS
    Recursively renames files in a folder by changing their file extensions.

.DESCRIPTION
    This script searches for files with a specified extension in a folder (including subfolders)
    and renames them to have a new extension. It provides a safe and efficient way to batch
    rename media files or other file types throughout a directory structure.

    FEATURES:
    ? Recursive directory scanning
    ? Batch file renaming
    ? Error handling and validation
    ? Detailed progress reporting
    ? Support for wildcard matching

.PARAMETER FolderPath
    Specifies the root folder path to scan for files to rename. The script will recursively
    search all subfolders. This parameter accepts UNC paths and local paths.

    Type: String
    Position: 0
    Required: True
    Default: '\\pvr\series\folder'

.PARAMETER OldExtension
    Specifies the current file extension to search for (include the dot). The script will
    only match files with this exact extension.

    Type: String
    Position: 1
    Required: False
    Default: '.mp4'

.PARAMETER NewExtension
    Specifies the new file extension to apply to matched files (include the dot).

    Type: String
    Position: 2
    Required: False
    Default: '.mkv'

.INPUTS
    String
    You can pipe folder paths, old extensions, and new extensions to this script.

.OUTPUTS
    PSCustomObject with the following properties:
    ? Status: 'Success' or 'Error'
    ? FolderPath: Path that was processed
    ? OldExtension: Extension searched for
    ? NewExtension: Extension applied
    ? FilesFound: Total files matching criteria
    ? FilesRenamed: Number of successfully renamed files
    ? FilesFailed: Number of files that failed to rename
    ? Message: Summary message or error details
    ? Timestamp: Operation completion time

    Exit Codes:
    ? 0: Success - All files renamed successfully
    ? 1: Error - Folder path does not exist or is inaccessible
    ? 2: Error - No files found matching the specified extension
    ? 3: Error - One or more rename operations failed

.EXAMPLE
    PS> .\Rename Extension.ps1 -FolderPath "C:\Videos" -OldExtension ".mp4" -NewExtension ".mkv"
    Renames all .mp4 files in C:\Videos and subfolders to .mkv

.EXAMPLE
    PS> .\Rename Extension.ps1 -FolderPath "\\server\media" -OldExtension ".avi" -NewExtension ".mp4"
    Renames all .avi files on a network share to .mp4

.EXAMPLE
    PS> .\Rename Extension.ps1 -FolderPath "C:\Downloads" -OldExtension ".tmp" -NewExtension ".bak" -Verbose
    Renames .tmp files to .bak with verbose output for detailed progress tracking

.NOTES
    Script Name    : Rename Extension.ps1
    Author         : DevOps Team
    Created        : 2026-03-14
    Version        : 1.0.0
    Last Updated   : 2026-03-14
    License        : MIT
    Prerequisites  : PowerShell 5.0 or higher

    Version History:
    V1.0 (2026-03-14) - Initial release with recursive directory support and error handling

    Error Codes:
    0  - Success: All files renamed successfully
    1  - Error: Folder path does not exist or is inaccessible
    2  - Error: No files found matching the specified extension
    3  - Error: One or more rename operations failed

.COMPONENT
    File Management Utilities

.ROLE
    Enterprise File System Administration

.FUNCTIONALITY
    File Renaming, Batch Operations, Media File Management

.LINK
    https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-item

#>

# Change these values as needed
param(
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Specify the folder path containing the files to rename.' , Mandatory = $true, Position = 0, ParameterSetName = 'Default')]
	[string]$folderPath = '\\pvr\series\folder',  # Folder containing the files
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Specify the current file extension to look for (include the dot).' , Mandatory = $false, Position = 1, ParameterSetName = 'Default')]
	[string]$oldExtension = '.mp4',                    # Current extension (include the dot)
	[parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, HelpMessage = 'Specify the new file extension to use (include the dot).' , Mandatory = $false, Position = 2, ParameterSetName = 'Default')]
	[string]$newExtension = '.mkv'                     # New extension (include the dot)
)

# Initialize result object
$result = [PSCustomObject]@{
	Status       = 'Error'
	FolderPath   = $folderPath
	OldExtension = $oldExtension
	NewExtension = $newExtension
	FilesFound   = 0
	FilesRenamed = 0
	FilesFailed  = 0
	Message      = ''
	Timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
}

try {
	# Validate folder path
	Write-Verbose "Validating folder path: $folderPath"
	if (-not (Test-Path -Path $folderPath -PathType Container)) {
		$result.Message = "Folder path '$folderPath' does not exist or is inaccessible."
		Write-Verbose "Folder validation failed: $($result.Message)"
		$result
		exit 1
	}

	# Get all files with the old extension
	Write-Verbose "Scanning for files with extension '$oldExtension' in '$folderPath'"
	$files = Get-ChildItem -Path $folderPath -Filter "*$oldExtension" -File -Recurse -ErrorAction Stop

	$result.FilesFound = @($files).Count

	if ($result.FilesFound -eq 0) {
		$result.Message = "No files found with extension '$oldExtension' in '$folderPath'."
		Write-Verbose $result.Message
		$result
		exit 2
	}

	Write-Verbose "Found $($result.FilesFound) file(s) matching criteria. Starting rename operation..."

	# Process each file
	foreach ($file in $files) {
		try {
			$newName = [System.IO.Path]::ChangeExtension($file.Name, $newExtension)
			Write-Verbose "Renaming: $($file.FullName) -> $newName"

			Rename-Item -Path $file.FullName -NewName $newName -ErrorAction Stop
			$result.FilesRenamed++

		} catch {
			$result.FilesFailed++
			Write-Verbose "Failed to rename '$($file.Name)': $($_.Exception.Message)"
		}
	}

	# Determine overall status
	if ($result.FilesFailed -eq 0) {
		$result.Status = 'Success'
		$result.Message = "Successfully renamed $($result.FilesRenamed) file(s) from $oldExtension to $newExtension."
		Write-Verbose $result.Message
		$result
		exit 0
	} else {
		$result.Status = 'Error'
		$result.Message = "Renamed $($result.FilesRenamed) file(s) successfully, but $($result.FilesFailed) file(s) failed."
		Write-Verbose $result.Message
		$result
		exit 3
	}

} catch {
	$result.Status = 'Error'
	$result.Message = "Unexpected error: $($_.Exception.Message)"
	Write-Verbose "Exception caught: $($_.Exception | Format-List * -Force | Out-String)"
	$result
	exit 3
}

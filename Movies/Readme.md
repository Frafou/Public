# IMDb Movie and Media Management Utilities

Complete PowerShell solution for IMDb data retrieval, media file organization, and video codec optimization. Includes scripts for movie/episode information lookup, file renaming, and HEVC video conversion.

## ?? Script Overview

### Get-MovieInfo.ps1

**Purpose**: Retrieve comprehensive movie information from IMDb using movie title or IMDb ID

**Key Features**:

- **Flexible Search Options**: Query by movie title or exact IMDb ID (tt format)
- **Comprehensive Data Retrieval**: Returns title, year, rating, plot, cast, director, awards, and more
- **Case-Insensitive Search**: Handles title variations and mixed-case searches
- **Error Handling**: Graceful handling of invalid searches and API errors
- **Pipeline-Friendly**: Accepts IMDb IDs via PowerShell pipeline
- **Structured Output**: Returns PSCustomObject with organized movie properties
- **API Validation**: Checks response validity and provides meaningful error messages

**Output Properties**:

- **Title**: Movie name
- **Year**: Release year
- **Rated**: Content rating (G, PG, PG-13, R, NC-17, etc.)
- **Released**: Full release date
- **Runtime**: Duration in minutes
- **Genre**: Genre categories
- **Director**: Director name(s)
- **Writer**: Screenplay writer(s)
- **Actors**: Main cast members
- **Plot**: Movie synopsis
- **Language**: Language(s)
- **Country**: Country/countries of origin
- **Awards**: Awards and nominations
- **IMDbRating**: IMDb user rating (out of 10)

### Get-ImdbEpisode.ps1

**Purpose**: Retrieve detailed episode information from TV series via OMDb API

**Key Features**:

- **Episode-Specific Queries**: Retrieve exact TV series episodes by season and episode number
- **Complete Episode Metadata**: Returns all episode details including plot, cast, and ratings
- **Series Title Validation**: Queries by exact series name
- **URL Encoding Support**: Handles special characters in series titles
- **Structured Episode Data**: Returns comprehensive episode information in PSCustomObject format
- **Verbose Output**: Detailed episode information displayed via verbose stream
- **Error Recovery**: Robust error handling for invalid series/season/episode combinations

**Output Properties**:

- **Title**: Episode title
- **Year**: Release year
- **Season**: Season number
- **Episode**: Episode number
- **Rated**: Content rating
- **Released**: Air date
- **Runtime**: Episode duration
- **Genre**: Genre classification
- **Director**: Episode director
- **Writer**: Episode writer(s)
- **Actors**: Cast members
- **Plot**: Episode synopsis
- **Awards**: Any awards or nominations

### Set-EpisodeFilenamev1.1.ps1

**Purpose**: Automate TV episode file renaming using IMDb episode titles

**Key Features**:

- **Recursive Directory Processing**: Scans all subdirectories for matching episode files
- **Pattern Recognition**: Automatically detects S##E## episode patterns (case-insensitive)
- **IMDb Integration**: Fetches episode titles from IMDb for accurate naming
- **Filename Sanitization**: Removes invalid filename characters automatically
- **Extension Preservation**: Maintains original file extensions during rename
- **Dependency Validation**: Verifies Get-ImdbEpisode.ps1 is available before processing
- **Color-Coded Output**: Provides color-coded success and error messages for easy tracking
- **Error Recovery**: Gracefully handles missing patterns and API errors

**Parameters**:

- **SeriesTitle** (Mandatory): Name of the TV series (e.g., "Breaking Bad", "The Office")
- **Path** (Optional): Directory containing episode files. Default: "D:\Videos\Series\$SeriesTitle"

**Output Naming Format**: `S##E## - [Episode Title].[original extension]`

**Example Transformations**:

- `S01E01.mkv` ? `S01E01 - Pilot.mkv`
- `s1e2_raw.mp4` ? `S01E02 - Cat's in the Bag.mp4`
- `season2_episode5.avi` ? `S02E05 - Salud.avi`

### Rename-FileExtension.ps1

**Purpose**: Batch rename file extensions recursively throughout a directory structure

**Key Features**:

- **Recursive Scanning**: Searches all subdirectories for matching file extensions
- **Safe Batch Operations**: Efficiently renames multiple files with validation
- **Extension Filtering**: Targets specific file types with exact extension matching
- **Path Flexibility**: Supports local paths and UNC network paths
- **Error Handling**: Comprehensive error handling and validation
- **Detailed Reporting**: Provides detailed progress and operation reporting
- **Wildcard Support**: Supports flexible file matching patterns

**Parameters**:

- **FolderPath** (Mandatory): Root directory to scan recursively
- **OldExtension** (Optional): Current extension to find (include dot, e.g., ".mp4"). Default: ".mp4"
- **NewExtension** (Optional): New extension to apply (include dot, e.g., ".mkv"). Default: ".mkv"

**Output**: Returns PSCustomObject with Status, FolderPath, and operation details

**Example Use Cases**:

```powershell
# Convert all MP4 files to MKV in series directory
.\Rename-FileExtension.ps1 -FolderPath "D:\Videos\Series" -OldExtension ".mp4" -NewExtension ".mkv"

# Change AVI files to MP4 on network share
.\Rename-FileExtension.ps1 -FolderPath "\\server\share\media" -OldExtension ".avi" -NewExtension ".mp4"
```

### StreamShift.ps1

**Purpose**: Automated HEVC video conversion for bulk media library optimization

**Key Features**:

- **Intelligent Format Detection**: Automatically identifies non-HEVC video files requiring conversion
- **Codec Analysis**: Uses FFprobe to analyze video streams before processing
- **Container Optimization**: Converts MP4 to MKV format for improved codec compatibility
- **Quality Preservation**: Uses CRF 23 for visually lossless quality with optimal compression
- **HEVC Encoding**: Encodes videos using x265 codec with medium preset for balanced speed/compression
- **Recursive Processing**: Scans all subdirectories for video content
- **Comprehensive Logging**: Detailed logs with timestamped entries for all operations
- **CSV Reporting**: Exports conversion results to CSV for tracking and analysis
- **Flexible Operation**: Supports log-only analysis or full conversion modes
- **Audio Preservation**: Copies original audio streams without re-encoding

**Supported Input Formats**:

- MP4 (H.264/AVC and other legacy codecs)
- AVI (various codecs)
- MOV (QuickTime format)
- WMV (Windows Media Video)
- FLV (Flash Video)
- MKV (non-HEVC encoded)

**Output Specifications**:

- **Codec**: x265 HEVC (H.265) - Modern, efficient codec
- **Container**: MKV (Matroska) - Better metadata support than MP4
- **Quality**: CRF 23 (visually lossless for most content)
- **Preset**: Medium (balances encoding speed with compression efficiency)
- **Audio**: Original streams copied (no re-encoding)
- **Subtitles**: All subtitle tracks preserved
- **Typical Size Reduction**: 20-50% file size reduction while maintaining quality

**Parameters**:

- **InputPath** (Optional): Root directory containing videos. Default: "\\server\share\video"

**Benefits**:

- Significantly reduces storage space requirements (typically 20-50% savings)
- Improves compatibility with modern streaming devices
- Optimizes long-term archival storage efficiency
- Automates processing for large media libraries
- Non-destructive operation with comprehensive logging

**Prerequisites**:

- **FFmpeg & FFprobe**: Video processing tools (visit <https://ffbinaries.com/>)
- **PowerShell**: Version 5.1 minimum
- **Storage Space**: Sufficient disk space for video processing
- **CPU Resources**: Multi-core CPU recommended for encoding efficiency

## ?? Quick Start

### Prerequisites

- **PowerShell**: Version 5.1 or higher
- **Internet Connection**: Required for OMDb API access (Get-MovieInfo, Get-ImdbEpisode)
- **OMDb API Key**: Free API key from [http://www.omdbapi.com/apikey.aspx](http://www.omdbapi.com/apikey.aspx)
- **FFmpeg Tools**: For StreamShift.ps1 video conversion

### Installation

```powershell
# OMDb API Key Registration (for IMDb-based scripts)
# 1. Visit: http://www.omdbapi.com/apikey.aspx
# 2. Select the FREE tier
# 3. Register with your email
# 4. Verify your email address
# 5. API key will be provided (typically starts with a letter)

# Verify PowerShell version
$PSVersionTable.PSVersion

# Copy scripts to your desired location
Copy-Item Get-MovieInfo.ps1 -Destination "C:\Scripts\Movies\"
Copy-Item Get-ImdbEpisode.ps1 -Destination "C:\Scripts\Movies\"
Copy-Item Set-EpisodeFilenamev1.1.ps1 -Destination "C:\Scripts\Movies\"
Copy-Item Rename-FileExtension.ps1 -Destination "C:\Scripts\Movies\"
Copy-Item StreamShift.ps1 -Destination "C:\Scripts\Movies\"

# For FFmpeg (required for StreamShift):
# Using Chocolatey:
choco install ffmpeg

# Using WinGet:
winget install Gyan.FFmpeg

# Using Scoop:
scoop install ffmpeg

# Verify FFmpeg installation
ffmpeg -version
ffprobe -version
```

### Basic Usage

```powershell
# Navigate to script directory
cd "C:\Scripts\Movies"

# Search for a movie by title
.\Get-MovieInfo.ps1 -Title "Inception" -ApiKey "YOUR_API_KEY"

# Search for a movie by IMDb ID
.\Get-MovieInfo.ps1 -IMDbID "tt1375666" -ApiKey "YOUR_API_KEY"

# Use default API key (if configured)
.\Get-MovieInfo.ps1 -Title "The Matrix"

# Retrieve specific TV episode
.\Get-ImdbEpisode.ps1 -SeriesTitle "Breaking Bad" -Season 1 -Episode 1 -ApiKey "YOUR_API_KEY"

# Pipe IMDb ID to Get-MovieInfo
"tt0111161" | .\Get-MovieInfo.ps1 -ApiKey "YOUR_API_KEY"

# Enable verbose output for detailed information
.\Get-ImdbEpisode.ps1 -SeriesTitle "The Office" -Season 2 -Episode 5 -Verbose
```

### Configuration

```powershell
# Set default API key in script (optional but recommended)
# Edit the ApiKey parameter default value in the script:

# In Get-MovieInfo.ps1, line ~28:
[Parameter(Mandatory = $False)]
[string]$ApiKey = "YOUR_API_KEY"   # Replace with your OMDb API key

# In Get-ImdbEpisode.ps1, line ~20:
[Parameter(Mandatory = $False)]
[string]$ApiKey = "YOUR_API_KEY"   # Replace with your OMDb API key
```

## ?? Use Cases and Workflows

### Media Library Workflows

#### Complete Media Organization Pipeline

```powershell
# Step 1: Rename video files from MP4 to MKV format
.\Rename-FileExtension.ps1 -FolderPath "D:\Videos\Series\Fallout" -OldExtension ".mp4" -NewExtension ".mkv"

# Step 2: Rename episode files with IMDb titles
.\Set-EpisodeFilenamev1.1.ps1 -SeriesTitle "Fallout" -Path "D:\Videos\Series\Fallout"

# Step 3: Convert videos to HEVC for storage optimization
.\StreamShift.ps1 -InputPath "D:\Videos\Series\Fallout"

# Step 4: Verify episode data in your library
.\Get-ImdbEpisode.ps1 -SeriesTitle "Fallout" -Season 1 -Episode 1 -ApiKey "YOUR_API_KEY"
```

#### Movie Collection Management

```powershell
# Retrieve and organize movie information
.\Get-MovieInfo.ps1 -Title "Inception" -ApiKey "YOUR_API_KEY" | Export-Csv "movie_metadata.csv"

# Search for multiple movies and create inventory
$movies = @("The Dark Knight", "Interstellar", "The Matrix")
foreach ($movie in $movies) {
    .\Get-MovieInfo.ps1 -Title $movie -ApiKey "YOUR_API_KEY" | Export-Csv "movie_library.csv" -Append
}
```

#### TV Series Batch Processing

```powershell
# Process multiple TV series episodes
$series = @("Breaking Bad", "The Office", "Game of Thrones")
foreach ($show in $series) {
    # Rename files with episode titles
    .\Set-EpisodeFilenamev1.1.ps1 -SeriesTitle $show -Path "D:\Videos\Series\$show"

    # Convert to HEVC
    .\StreamShift.ps1 -InputPath "D:\Videos\Series\$show"
}
```

### Storage Optimization Workflows

```powershell
# Analyze and convert large video collection (log-only first)
.\StreamShift.ps1 -InputPath "E:\Videos" -Verbose

# Example: Convert specific codec formats
.\Rename-FileExtension. -FolderPath "E:\Videos\Archive" -OldExtension ".avi" -NewExtension ".mkv"
```

### Content Research Workflows

```powershell
# Research movie details before watching
$movie = .\Get-MovieInfo.ps1 -Title "Parasite" -ApiKey "YOUR_API_KEY"
Write-Host "Rating: $($movie.Rated) | IMDb: $($movie.IMDbRating) | Director: $($movie.Director)"

# Verify episode information before organizing files
$episode = .\Get-ImdbEpisode.ps1 -SeriesTitle "Breaking Bad" -Season 1 -Episode 1 -ApiKey "YOUR_API_KEY"
Write-Host "Episode: $($episode.Title) | Plot: $($episode.Plot)"
```

## ?? Advanced Features and Examples

### File Organization Workflows

#### Rename Files by Extension

```powershell
# Basic usage - convert all MP4 to MKV
.\Rename-FileExtension.ps1 -FolderPath "D:\Videos"

# Recursive conversion on network share
.\Rename-FileExtension.ps1 -FolderPath "\\nas\media\videos" -OldExtension ".avi" -NewExtension ".mkv"

# Check results
Get-ChildItem -Path "D:\Videos" -Recurse -Filter "*.mkv" | Measure-Object | Select-Object Count
```

#### Episode File Renaming

```powershell
# Rename Breaking Bad episodes
.\Set-EpisodeFilenamev1.1.ps1 -SeriesTitle "Breaking Bad" -Path "D:\Videos\Series\BreakingBad"

# Rename with custom path
.\Set-EpisodeFilenamev1.1.ps1 -SeriesTitle "The Office" -Path "E:\TV Shows\The Office"

# Process complete series collection using loop
$seriesList = @(
    @{Title = "Breaking Bad"; Path = "D:\Videos\Series\BreakingBad"},
    @{Title = "Game of Thrones"; Path = "D:\Videos\Series\GameOfThrones"},
    @{Title = "The Office"; Path = "D:\Videos\Series\TheOffice"}
)

foreach ($series in $seriesList) {
    Write-Host "Processing $($series.Title)..."
    .\Set-EpisodeFilenamev1.1.ps1 -SeriesTitle $series.Title -Path $series.Path
}
```

#### Video Format Conversion

```powershell
# Convert entire media library to HEVC (analysis mode first)
.\StreamShift.ps1 -InputPath "E:\Videos" -Verbose

# Convert specific directory
.\StreamShift.ps1 -InputPath "E:\Movies"

# Monitor conversion progress
Get-ChildItem -Path "E:\Videos" -Recurse -Filter "*.mkv" | Measure-Object -Property Length -Sum | `
    Select-Object Count, @{Name="Total_GB"; Expression={$_.Sum / 1GB}}
```

### Data Integration and Export

```powershell
# Export movie metadata
$movie = .\Get-MovieInfo.ps1 -Title "The Shawshank Redemption" -ApiKey "YOUR_API_KEY"
$movie | Export-Csv "movie_metadata.csv" -NoTypeInformation

# Export multiple episodes
$episodes = 1..10
foreach ($ep in $episodes) {
    .\Get-ImdbEpisode.ps1 -SeriesTitle "Breaking Bad" -Season 1 -Episode $ep -ApiKey "YOUR_API_KEY" | `
    Export-Csv "breaking_bad_s1.csv" -Append -NoTypeInformation
}

# Format output as table
.\Get-ImdbEpisode.ps1 -SeriesTitle "The Office" -Season 1 -Episode 1 -ApiKey "YOUR_API_KEY" | Format-Table -AutoSize
```

### Error Handling and Validation

```powershell
# Error handling for IMDb lookups
try {
    $movie = .\Get-MovieInfo.ps1 -Title "NonexistentMovie" -ApiKey "YOUR_API_KEY"
    if ($movie.Response -eq "False") {
        Write-Warning "Movie not found: $($movie.Error)"
    }
} catch {
    Write-Error "API Error: $_"
}

# Validate episode file pattern before processing
$files = Get-ChildItem "D:\Videos\Series" -Filter "*S*E*" -Recurse
Write-Host "Found $($files.Count) potential episode files"

# Validate directory exists before file operations
if ((Test-Path "D:\Videos\Series\MyShow") -eq $false) {
    Write-Error "Series directory not found"
    exit 1
}
```

### Batch Processing Examples

```powershell
# Process multiple movies
$movies = @("Inception", "The Dark Knight", "Interstellar", "The Matrix", "Parasite")
$results = @()

foreach ($title in $movies) {
    $result = .\Get-MovieInfo.ps1 -Title $title -ApiKey "YOUR_API_KEY"
    $results += $result
}

$results | Export-Csv "movie_collection.csv" -NoTypeInformation
$results | Format-Table -AutoSize

# Batch extension renaming with reporting
$directories = @("D:\Videos\Movies", "D:\Videos\TV Shows", "D:\Videos\Archive")

foreach ($dir in $directories) {
    if (Test-Path $dir) {
        Write-Host "Processing: $dir"
        .\Rename-FileExtension.ps1 -FolderPath $dir -OldExtension ".avi" -NewExtension ".mkv"
    }
}
```

### Pipeline Integration

```powershell
# Export movie data with filtering
.\Get-MovieInfo.ps1 -Title "The Dark Knight" -ApiKey "YOUR_API_KEY" | `
    Select-Object Title, Year, IMDbRating, Director, Actors | `
    Export-Csv "movie_summary.csv"

# Process episode data through pipeline
.\Get-ImdbEpisode.ps1 -SeriesTitle "Breaking Bad" -Season 1 -Episode 1 -ApiKey "YOUR_API_KEY" | `
    Format-Table -Property Title, Season, Episode, Plot -Wrap

# Combine file operations with IMDb data
Get-ChildItem "D:\Videos\Series\Fallout" -Filter "*.mkv" -Recurse | ForEach-Object {
    Write-Host "File: $($_.Name)"
    # Additional processing here
}
```

## ?? API and Tool Information

### OMDb API Details

- **Base URL**: <http://www.omdbapi.com/>
- **Rate Limit**: 1,000 requests per day (free tier)
- **Response Format**: JSON (automatically converted to PSCustomObject)
- **Authentication**: Query parameter apikey=YOUR_KEY
- **Documentation**: <http://www.omdbapi.com/>

### API Parameters

**Get-MovieInfo.ps1 Parameters**:

- `t` (Parameter: -Title): Movie title to search
- `i` (Parameter: -IMDbID): IMDb ID for exact lookup
- `apikey` (Parameter: -ApiKey): Your OMDb API key

**Get-ImdbEpisode.ps1 Parameters**:

- `t` (Parameter: -SeriesTitle): TV series title
- `Season` (Parameter: -Season): Season number
- `Episode` (Parameter: -Episode): Episode number
- `apikey` (Parameter: -ApiKey): Your OMDb API key

## ?? Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "API returned error" | Verify your API key is valid and active |
| "No results found" | Check movie title spelling; try exact IMDb ID instead |
| "Rate limit exceeded" | Wait 24 hours or upgrade to a paid OMDb subscription |
| "Connection timeout" | Verify internet connectivity and OMDb API availability |
| "Invalid season/episode" | Verify season and episode numbers exist for the series |

### Getting Help

- Check OMDb API status: <http://www.omdbapi.com/>
- Review script verbose output: Add `-Verbose` flag to scripts
- Verify API key: Visit <http://www.omdbapi.com/apikey.aspx>
- Test API manually: <http://www.omdbapi.com/?t=inception&apikey=YOUR_KEY>

## ?? Notes

- **License**: MIT
- **Last Updated**: March 22, 2026
- **Version**: 1.0.0
- **Author**: Your Name
- **Requirements**: PowerShell 5.1+, Internet connectivity, valid OMDb API key

## ?? Related Resources

- [OMDb API Documentation](http://www.omdbapi.com/)
- [IMDb Official Website](https://www.imdb.com/)
- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [Invoke-RestMethod](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod/)

- **Scalable Processing**: Handles libraries with thousands of video files
- **Resumable Operations**: Can safely restart after interruptions
- **Resource Management**: Efficient CPU and memory usage during encoding
- **Network Storage Support**: Compatible with SMB/CIFS and NFS shares

### Safety and Reliability

- **Non-Destructive Processing**: Original files preserved until successful conversion
- **Verification Checks**: Post-conversion file integrity validation
- **Graceful Error Handling**: Continues processing despite individual file failures
- **Rollback Capability**: Easy restoration of original files if needed

## ?? Requirements

### System Requirements

- **Operating System**: Windows 10/11, Windows Server 2016+, or Linux with PowerShell Core
- **CPU**: Multi-core processor (Intel Core i5/AMD Ryzen 5 or better recommended)
- **Memory**: 8GB RAM minimum, 16GB+ recommended for large files
- **Storage**: At least 2x the size of source video library for temporary files

### Software Dependencies

```powershell
# Required software versions
FFmpeg >= 4.0.0 (latest version recommended)
FFprobe >= 4.0.0 (included with FFmpeg)
PowerShell >= 5.1 (PowerShell 7+ preferred)
PSLogging module >= 2.5.0
```

### Network Requirements

- **Local Storage**: Recommended for optimal performance
- **Network Storage**: SMB 3.0+ or NFS 4.0+ for network attached storage
- **Bandwidth**: Sufficient network capacity if processing remote files

### Performance Considerations

- **Encoding Speed**: Approximately 1x to 4x real-time depending on CPU
- **Storage Requirements**: 150-200% of original library size during conversion
- **Processing Time**: Varies by CPU performance and video resolution/duration

## ?? Advanced Configuration

### Custom Quality Settings

```powershell
# Modify script for different quality levels
$crfValue = 23    # Default (23 = visually lossless)
$crfValue = 20    # Higher quality (larger files)
$crfValue = 26    # Lower quality (smaller files)

# Preset options for encoding speed vs compression
$preset = "medium"      # Balanced (default)
$preset = "slow"        # Better compression
$preset = "fast"        # Faster encoding
$preset = "veryslow"    # Maximum compression
```

### Automated Scheduling

```powershell
# Create scheduled task for automated processing
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\StreamShift.ps1"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 11:00PM
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -RestartCount 3
Register-ScheduledTask -TaskName "HEVC Video Conversion" `
    -Action $Action -Trigger $Trigger -Settings $Settings
```

### Integration with Media Servers

```powershell
# Pre-processing for Plex/Jellyfin media servers
# 1. Stop media server service
Stop-Service PlexMediaServer

# 2. Run conversion
.\StreamShift.ps1

# 3. Restart media server to scan new files
Start-Service PlexMediaServer
```

## ?? Troubleshooting

### Common Issues

**Issue**: "FFmpeg not found" or "FFprobe not found"
**Solution**: Ensure FFmpeg executables are in script directory or system PATH

**Issue**: "Insufficient disk space" errors
**Solution**: Verify available storage is at least 2x the source file size

**Issue**: "Access denied" or permission errors
**Solution**: Run PowerShell as Administrator and verify file/directory permissions

**Issue**: "Encoding failures" or "Corrupted output files"
**Solution**: Check source file integrity and verify FFmpeg installation

**Issue**: "Script execution policy" restrictions
**Solution**: Configure PowerShell execution policy: `Set-ExecutionPolicy RemoteSigned`

### Performance Optimization

```powershell
# Optimize for faster encoding (lower quality)
$preset = "faster"
$crfValue = 28

# Optimize for maximum quality (slower encoding)
$preset = "veryslow"
$crfValue = 18

# Enable hardware acceleration (if supported)
$hwAccel = "-hwaccel auto"  # Add to FFmpeg command line
```

### Debug Mode

```powershell
# Enable detailed debugging output
$DebugPreference = "Continue"
$VerbosePreference = "Continue"
.\StreamShift.ps1 -Verbose -Debug

# Generate detailed logs
.\StreamShift.ps1 -LogOnly > "conversion-analysis.log" 2>&1
```

## ?? Contributing

We welcome contributions to improve video conversion automation capabilities!

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/video-enhancement`)
3. **Follow** PowerShell best practices and media processing standards
4. **Add** comprehensive testing with various video formats
5. **Test** thoroughly with different CPU architectures and performance levels
6. **Update** documentation for any new functionality or parameters
7. **Commit** with clear, descriptive messages
8. **Submit** a pull request with detailed description and test results

### Development Standards

- Follow PowerShell Script Analyzer guidelines
- Include comprehensive error handling for media processing operations
- Add appropriate progress indicators for long-running conversions
- Maintain compatibility with various FFmpeg versions
- Document all quality and performance parameters
- Test with diverse video formats and resolutions

### Testing Guidelines

- Test with various input formats (MP4, AVI, MOV, WMV, etc.)
- Validate quality preservation across different content types
- Verify performance with large file libraries
- Test error handling and recovery scenarios
- Validate cross-platform compatibility

## ?? License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

## ?? Disclaimer

This code is provided for demonstration purposes only. It is intended to illustrate video processing automation concepts and should not be used in production environments without proper review, testing, and validation. The authors and distributors of this code make no warranties regarding its functionality, security, or suitability for any specific use. Use at your own risk.

**Video Processing Recommendations**:

- Always backup original video files before batch conversion
- Test conversion settings with sample files before processing entire libraries
- Monitor system resources during conversion to prevent overheating
- Verify output quality and file integrity after conversion
- Consider legal implications of video format conversion in your jurisdiction

## ?? Contact

For questions, feedback, or support regarding video conversion automation:

- **Email**: [GitHub@ffournier.ca](mailto:GitHub@ffournier.ca)
- **GitHub**: [@Frafou](https://github.com/Frafou)
- **Issues**: Use GitHub Issues for bug reports and feature requests

## ??? Tags

`PowerShell` `HEVC` `x265` `Video Conversion` `FFmpeg` `Media Processing` `Storage Optimization` `Batch Processing` `Automation` `Video Compression`

# HEVC Video Conversion Automation

Advanced PowerShell solution for automated video library optimization using x265 HEVC encoding, designed for efficient media storage and high-quality video compression.

## ?? Script Overview

### StreamShift_1.0.9.ps1

**Purpose**: Automated batch video conversion from legacy codecs to HEVC (H.265) for optimal storage efficiency

**Key Features**:

- **Intelligent Format Detection**: Automatically identifies non-HEVC video files requiring conversion
- **Recursive Directory Processing**: Scans specified directory and all subdirectories for video content
- **Smart File Handling**: Preserves original files while creating optimized HEVC versions
- **Quality Optimization**: Uses CRF 23 with medium preset for excellent quality-to-size ratio
- **Container Standardization**: Converts MP4 to MKV format for improved metadata support
- **Advanced Logging**: Comprehensive logging using PSLogging module with detailed progress tracking
- **Flexible Operation Modes**: Full conversion or log-only analysis modes
- **Error Recovery**: Robust error handling for interrupted conversions

**Supported Input Formats**:

- MP4 (H.264/AVC and other legacy codecs)
- AVI (various codecs)
- MOV (QuickTime format)
- WMV (Windows Media Video)
- FLV (Flash Video)
- MKV (non-HEVC encoded)

**Output Specifications**:

- **Codec**: x265 HEVC (H.265)
- **Container**: MKV (Matroska Video)
- **Quality**: CRF 23 (visually lossless for most content)
- **Preset**: Medium (balanced encoding speed and compression efficiency)
- **Audio**: Copy original streams (no re-encoding)
- **Subtitles**: Preserve all subtitle tracks

## ?? Quick Start

### Prerequisites

- **FFmpeg Suite**: FFmpeg and FFprobe executables (essential for video processing)
- **PowerShell**: Version 5.1 minimum (PowerShell 7+ recommended for performance)
- **PSLogging Module**: Auto-installed by script for comprehensive logging
- **Storage Space**: Sufficient disk space for both original and converted files
- **CPU Resources**: Multi-core CPU recommended for efficient x265 encoding

### Installation

```powershell
# Download FFmpeg and FFprobe binaries
# Visit: https://ffbinaries.com/
# Or use package managers:

# Using Chocolatey
choco install ffmpeg

# Using WinGet
winget install Gyan.FFmpeg

# Using Scoop
scoop install ffmpeg

# Verify installation
ffmpeg -version
ffprobe -version

# PSLogging module (auto-installed by script)
Install-Module PSLogging -Force
```

### Basic Usage

```powershell
# Navigate to script directory
cd "C:\Scripts\HEVC Conversion"

# Analysis mode - scan and report without converting
.\StreamShift_1.0.9.ps1 -LogOnly

# Full conversion mode - process all non-HEVC videos
.\StreamShift_1.0.9.ps1

# Specify custom target directory
.\StreamShift_1.0.9.ps1 -TargetPath "E:\Videos\Movies"

# Verbose output for detailed monitoring
.\StreamShift_1.0.9.ps1 -Verbose
```

### Configuration

```powershell
# Edit script variables before execution
$targetDirectory = "C:\Videos"           # Base directory to process
$logPath = "C:\Logs\VideoConversion"     # Log file location
$ffmpegPath = ".\ffmpeg.exe"             # FFmpeg executable path
$ffprobePath = ".\ffprobe.exe"           # FFprobe executable path
```

## ?? Use Cases

### 1. Media Library Optimization

- Reduce storage requirements for large video collections
- Maintain high video quality while achieving 40-60% size reduction
- Standardize video formats across mixed-codec libraries
- Future-proof media collections with modern HEVC encoding

### 2. Storage Cost Management

- Cloud storage cost reduction through efficient compression
- Network attached storage (NAS) optimization
- Bandwidth savings for media streaming and transfers
- Long-term archival storage optimization

### 3. Content Preparation

- Prepare videos for mobile device consumption
- Optimize content for streaming platforms
- Reduce file sizes for email and web distribution
- Create space-efficient backup copies

### 4. Batch Processing Workflows

- Automated overnight conversion processing
- Integration with media server maintenance routines
- Scheduled library optimization tasks
- Post-download processing automation

## ?? Features

### Advanced Video Processing

- **Format Intelligence**: Automatically detects codec types and skips already-converted HEVC content
- **Quality Preservation**: CRF 23 encoding maintains visual quality while optimizing file size
- **Metadata Retention**: Preserves video metadata, creation dates, and file attributes
- **Audio Stream Handling**: Copies all audio tracks without re-encoding to prevent quality loss

### Comprehensive Logging

- **Detailed Progress Tracking**: Real-time conversion progress with time estimates
- **Error Documentation**: Complete error logging with troubleshooting context
- **Performance Metrics**: Encoding speed, compression ratios, and processing statistics
- **Audit Trail**: Complete record of all conversions and file operations

### Enterprise-Ready Operations

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
    -Argument "-File C:\Scripts\StreamShift_1.0.9.ps1"
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
.\StreamShift_1.0.9.ps1

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
.\StreamShift_1.0.9.ps1 -Verbose -Debug

# Generate detailed logs
.\StreamShift_1.0.9.ps1 -LogOnly > "conversion-analysis.log" 2>&1
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

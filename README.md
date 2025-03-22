# HEVC Conversion

# Synopsis:
This PowerShell script re-encodes non-HEVC video files in a specified directory and its subdirectories using x265 HEVC video codec with a medium preset and 23 quality.

# Description:
The PowerShell script scans a directory and its subdirectories for non-HEVC video files, renames them and converts any MP4 files to MKV, then re-encodes the videos using the x265 HEVC codec and a medium preset with a 23 quality.

#Requirements: 
1. **ffmpeg** and **ffprobe** which can be downloaded at **https://ffbinaries.com/**
2. **PSLogging** module which teh script will install

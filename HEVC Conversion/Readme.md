# HEVC Conversion

## Synopsis

This PowerShell script re-encodes non-HEVC video files in a specified directory and its subdirectories using x265 HEVC video codec with a medium preset and 23 quality.

## Description

The PowerShell script scans a directory and its subdirectories for non-HEVC video files, renames them and converts any MP4 files to MKV, then re-encodes the videos using the x265 HEVC codec and a medium preset with a 23 quality.

## Requirements

1. **ffmpeg** and **ffprobe** which can be downloaded at **<https://ffbinaries.com/>**
2. **PSLogging** module which teh script will install

## Features

- Convert Non-HEVC file to HEVC format
- LogOnly

## Installation

Instructions on how to install and set up your project.

## Copy File

Copy PS1 file to a local Folder

## Navigate to the directory

cd Folder

## Install dependencies

Download **ffmpeg** and **ffprobe** to the scripts location
Configure variables

## Execute the script

PS:> .\StreamShift_1.0.8.ps1
PS:> .\StreamShift_1.0.8.ps1 -LogOnly

## Contributing

Guidelines for contributing to your project.

1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -m 'Add some feature').
5. Push to the branch (git push origin feature-branch).
6. Open a pull request.

## License

MIT license.

## Contact

How to reach you for questions or feedback.

Email: <GitHub@ffournier.ca>
GitHub: Frafou

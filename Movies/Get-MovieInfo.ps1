<#
.SYNOPSIS
    Retrieves comprehensive movie information from IMDb via the OMDb API.

.DESCRIPTION
    This script queries the OMDb API to fetch detailed information about a movie using either
    the movie title or IMDb ID. Returns comprehensive metadata including title, year, rating,
    plot, cast, director, and awards information.
    Requires a free API key from http://www.omdbapi.com/apikey.aspx.

.PARAMETER Title
    The movie title to search for. Performs a search query by title name.
    Supports partial matches and is case-insensitive.

.PARAMETER IMDbID
    The IMDb ID (e.g., tt0111161) to search for. Provides exact lookup by IMDb identifier.
    Must be in the format tt followed by numeric digits.

.PARAMETER ApiKey
    Your OMDb API key. Free API key can be obtained from http://www.omdbapi.com/apikey.aspx
    Default value is provided but should be replaced with your own key for production use.

.INPUTS
    System.String
        Title parameter accepts string pipeline input for movie titles.
    System.String
        IMDbID parameter accepts string pipeline input for IMDb identifiers.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        Returns an object containing movie properties (Title, Year, Rated, Released, Runtime,
        Genre, Director, Writer, Actors, Plot, Language, Country, Awards, IMDbRating, etc.)

.EXAMPLE
    .\Get-MovieInfo.ps1 -Title "Inception" -ApiKey "your_api_key"
    Retrieves movie information for "Inception" using the provided API key.

.EXAMPLE
    .\Get-MovieInfo.ps1 -IMDbID "tt1375666" -ApiKey "your_api_key"
    Retrieves exact movie information using the IMDb ID for Inception.

.EXAMPLE
    Get-MovieInfo.ps1 -Title "The Matrix"
    Retrieves movie information using the default API key.

.EXAMPLE
    "tt0111161" | .\Get-MovieInfo.ps1 -ApiKey "your_api_key"
    Retrieves movie information by piping an IMDb ID to the script.

.NOTES
    Author: Your Name
    Created: 2026-03-22
    Version: 1.0.0
    Last Updated: 2026-03-22
    License: MIT

    V1.0 Initial version - Basic movie information retrieval by title or IMDb ID

    REQUIREMENTS:
    - Valid OMDb API key from http://www.omdbapi.com/apikey.aspx
    - Internet connectivity to reach OMDb API
    - PowerShell 5.1 or higher

    ERROR CODES:
    1 - No Title or IMDbID provided
    2 - API request failed or no results found

.COMPONENT
    IMDb Movie Information Retrieval Utility
    Part of the Movies collection scripts

.ROLE
    Data Retrieval Utility

.FUNCTIONALITY
    OMDb API Integration - Movie Information Lookup

.LINK
    http://www.omdbapi.com/
    OMDb API Documentation

.LINK
    https://www.imdb.com/
    IMDb Website
#>

#Requires -Version 5.1

[CmdletBinding()]
param (
    [string]$Title,
    [string]$IMDbID,
    [Parameter(Mandatory = $False)]
    [string]$ApiKey = 'xxxx'
)

# Validate input
if (-not $Title -and -not $IMDbID) {
    Write-Error 'You must provide either -Title or -IMDbID.'
    exit 1
}

try {
    # Build the query URL
    if ($Title) {
        $encodedTitle = [System.Web.HttpUtility]::UrlEncode($Title)
        $url = "http://www.omdbapi.com/?t=$encodedTitle&apikey=$ApiKey"
    } elseif ($IMDbID) {
        $url = "http://www.omdbapi.com/?i=$IMDbID&apikey=$ApiKey"
    }

    # Call the API
    $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

    # Check if the API returned a valid result
    if ($response.Response -eq 'False') {
        Write-Warning "No results found: $($response.Error)"
    } else {
        # Display selected movie details
        [PSCustomObject]@{
            Title      = $response.Title
            Year       = $response.Year
            Rated      = $response.Rated
            Released   = $response.Released
            Runtime    = $response.Runtime
            Genre      = $response.Genre
            Director   = $response.Director
            Writer     = $response.Writer
            Actors     = $response.Actors
            Plot       = $response.Plot
            Language   = $response.Language
            Country    = $response.Country
            Awards     = $response.Awards
            IMDbRating = $response.imdbRating
            IMDbVotes  = $response.imdbVotes
            IMDbID     = $response.imdbID
            Type       = $response.Type
        }
    }
} catch {
    Write-Error "Error retrieving movie information: $_"
}

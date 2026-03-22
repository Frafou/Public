<#
.SYNOPSIS
    Retrieves episode information from IMDb via the OMDb API.

.DESCRIPTION
    Uses the OMDb API to fetch details for a specific episode of a TV series.
    Requires a free API key from http://www.omdbapi.com/apikey.aspx.
    Returns comprehensive episode metadata including title, plot, cast, and ratings.

.PARAMETER ApiKey
    Your OMDb API key. Free API key can be obtained from http://www.omdbapi.com/apikey.aspx
    Default value is provided but should be replaced with your own key for production use.

.PARAMETER SeriesTitle
    The exact title of the TV series. Must match the IMDb series title.

.PARAMETER Season
    The season number. Must be a positive integer.

.PARAMETER Episode
    The episode number. Must be a positive integer.

.INPUTS
    System.String
        SeriesTitle parameter accepts string pipeline input.
    System.Int32
        Season and Episode parameters accept integer values.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        Returns an object containing episode properties (Title, Plot, Actors, Director, etc.)

    Log Output
        Verbose messages containing detailed episode information are written to the verbose stream.

.EXAMPLE
    .\Get-ImdbEpisode.ps1 -ApiKey "YOUR_KEY" -SeriesTitle "Breaking Bad" -Season 1 -Episode 1
    Retrieves episode 1 from season 1 of Breaking Bad.

.EXAMPLE
    .\Get-ImdbEpisode.ps1 -SeriesTitle "The Office" -Season 2 -Episode 5 -Verbose
    Retrieves episode 5 from season 2 of The Office and displays verbose output.

.EXAMPLE
    Get-ImdbEpisode.ps1 -ApiKey "YOUR_KEY" -SeriesTitle "Game of Thrones" -Season 5 -Episode 8
    Retrieves specific episode using default or custom API key.

.NOTES
    Author: Your Name
    Created: 2026-03-22
    Version: 1.0.0
    Last Updated: 2026-03-22
    License: MIT

    V1.0 Initial version - Basic episode retrieval functionality

    REQUIREMENTS:
    - Valid OMDb API key from http://www.omdbapi.com/apikey.aspx
    - Internet connectivity to reach OMDb API
    - PowerShell 5.1 or higher

.COMPONENT
    IMDb Episode Retrieval Utility
    Part of the Movies collection scripts

.ROLE
    Data Retrieval Utility

.FUNCTIONALITY
    OMDb API Integration - Episode Information Lookup

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
    [Parameter(Mandatory = $False)]
    [string]$ApiKey = 'xxxx',

    [Parameter(Mandatory = $true)]
    [string]$SeriesTitle,

    [Parameter(Mandatory = $true)]
    [int]$Season,

    [Parameter(Mandatory = $true)]
    [int]$Episode
)

try {
    # Encode title for URL
    $encodedTitle = [System.Web.HttpUtility]::UrlEncode($SeriesTitle)

    # Build request URL
    $url = "http://www.omdbapi.com/?t=$encodedTitle&Season=$Season&Episode=$Episode&apikey=$ApiKey"

    # Call OMDb API
    $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

    if ($response.Response -eq 'False') {
        Write-Error "Error: $($response.Error)"
        exit 1
    }

    # Display episode info
    Write-Verbose "Title: $($response.Title)"
    Write-Verbose "Year: $($response.Year)"
    Write-Verbose "Rated: $($response.Rated)"
    Write-Verbose "Released: $($response.Released)"
    Write-Verbose "Season: $($response.Season)"
    Write-Verbose "Episode: $($response.Episode)"
    Write-Verbose "Runtime: $($response.Runtime)"
    Write-Verbose "Genre: $($response.Genre)"
    Write-Verbose "Director: $($response.Director)"
    Write-Verbose "Writer: $($response.Writer)"
    Write-Verbose "Actors: $($response.Actors)"
    Write-Verbose "Plot: $($response.Plot)"
    Write-Verbose "Language: $($response.Language)"
    Write-Verbose "Country: $($response.Country)"
    Write-Verbose "Awards: $($response.Awards)"
    Write-Verbose "Poster: $($response.Poster)"
    Write-Verbose "Ratings: $($response.Ratings)"
    Write-Verbose "Metascore: $($response.Metascore)"
    Write-Verbose "IMDb Rating: $($response.imdbRating)"
    Write-Verbose "IMDb Votes: $($response.imdbVotes)"
    Write-Verbose "IMDb ID: $($response.imdbID)"
    Write-Verbose "Series ID: $($response.seriesID)"
    Write-Verbose "Type: $($response.Type)"
    Write-Verbose "Response: $($response.Response)"

    $info = @{
        Title      = $response.Title
        Year       = $response.Year
        Rated      = $response.Rated
        Released   = $response.Released
        Season     = $response.Season
        Episode    = $response.Episode
        Runtime    = $response.Runtime
        Genre      = $response.Genre
        Director   = $response.Director
        Writer     = $response.Writer
        Actors     = $response.Actors
        Plot       = $response.Plot
        Language   = $response.Language
        Country    = $response.Country
        Awards     = $response.Awards
        Poster     = $response.Poster
        Ratings    = $response.Ratings
        Metascore  = $response.Metascore
        imdbRating = $response.imdbRating
        imdbVotes  = $response.imdbVotes
        imdbID     = $response.imdbID
        seriesID   = $response.seriesID
        Type       = $response.Type

    }

} catch {
    Write-Error "An error occurred: $_"
}

return $info

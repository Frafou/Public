<#
.SYNOPSIS
    Retrieves episode information from IMDb via the OMDb API.

.DESCRIPTION
    Uses the OMDb API to fetch details for a specific episode of a TV series.
    Requires a free API key from http://www.omdbapi.com/apikey.aspx.

.PARAMETER ApiKey
    Your OMDb API key.

.PARAMETER SeriesTitle
    The exact title of the TV series.

.PARAMETER Season
    The season number.

.PARAMETER Episode
    The episode number.

.PARAMETER EncodedTitle
    The encoded title of the TV series.

.EXAMPLE
    .\Get-ImdbEpisode.ps1 -ApiKey "YOUR_KEY" -SeriesTitle "Breaking Bad" -Season 1 -Episode 1
#>

param (
    [Parameter(Mandatory = $False, HelpMessage = 'Your OMDb API key.')]
    [string]$ApiKey = '5c256d54',

    [Parameter(Mandatory = $true, HelpMessage = 'The exact title of the TV series.')]
    [string]$SeriesTitle,

    [Parameter(Mandatory = $false, HelpMessage = 'The encoded title of the TV series.')]
    [string]$EncodedTitle,

    [Parameter(Mandatory = $true, HelpMessage = 'The season number.')]
    [int]$Season,

    [Parameter(Mandatory = $true, HelpMessage = 'The episode number.')]
    [int]$Episode
)

try {
    Write-Verbose '-----------------------------------------'
    Write-Verbose "Get-IMDBEpisodeV 2'n"
    # Encode title for URL
    if (-not $EncodedTitle) {
        $encodedTitle = [System.Web.HttpUtility]::UrlEncode($SeriesTitle)
    }
    Write-Verbose "EncodedTitle: $encodedTitle"
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
Write-Verbose 'end og Get-IMDBEpisode'
Write-Verbose '-----------------------------------------'
return $info

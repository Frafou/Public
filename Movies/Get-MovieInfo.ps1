<#
.SYNOPSIS
    Retrieves movie information from IMDb via the OMDb API.

.DESCRIPTION
    This script queries the OMDb API using a movie title or IMDb ID.
    Requires a free API key from http://www.omdbapi.com/apikey.aspx.

.PARAMETER Title
    The movie title to search for.

.PARAMETER IMDbID
    The IMDb ID (e.g., tt0111161) to search for.

.PARAMETER ApiKey
    Your OMDb API key.

.EXAMPLE
    .\Get-MovieInfo.ps1 -Title "Inception" -ApiKey "your_api_key"

.EXAMPLE
    .\Get-MovieInfo.ps1 -IMDbID "tt1375666" -ApiKey "your_api_key"
#>

param (
    [string]$Title,
    [string]$IMDbID,
    [Parameter(Mandatory = $False)]
    [string]$ApiKey = "5c256d54"
)

# Validate input
if (-not $Title -and -not $IMDbID) {
    Write-Error "You must provide either -Title or -IMDbID."
    exit 1
}

try {
    # Build the query URL
    if ($Title) {
        $encodedTitle = [System.Web.HttpUtility]::UrlEncode($Title)
        $url = "http://www.omdbapi.com/?t=$encodedTitle&apikey=$ApiKey"
    }
    elseif ($IMDbID) {
        $url = "http://www.omdbapi.com/?i=$IMDbID&apikey=$ApiKey"
    }

    # Call the API
    $response = Invoke-RestMethod -Uri $url -Method Get -ErrorAction Stop

    # Check if the API returned a valid result
    if ($response.Response -eq "False") {
        Write-Warning "No results found: $($response.Error)"
    }
    else {
        # Display selected movie details
        [PSCustomObject]@{
            Title       = $response.Title
            Year        = $response.Year
            Rated       = $response.Rated
            Released    = $response.Released
            Runtime     = $response.Runtime
            Genre       = $response.Genre
            Director    = $response.Director
            Writer      = $response.Writer
            Actors      = $response.Actors
            Plot        = $response.Plot
            Language    = $response.Language
            Country     = $response.Country
            Awards      = $response.Awards
            IMDbRating  = $response.imdbRating
            IMDbVotes   = $response.imdbVotes
            IMDbID      = $response.imdbID
            Type        = $response.Type
        }
    }
}
catch {
    Write-Error "Error retrieving movie information: $_"
}

function Format-Result {
<#
.SYNOPSIS
    Formats a response from the Falcon API
.PARAMETER RESPONSE
    Response object from a Falcon API request
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Response
    )
    process {
        if ($Response.Result.Content) {
            if ($Response.Result.Content -match '^<') {
                # Output HTML
                ($Response.Result.Content).ReadAsStringAsync().Result
            } else {
                # Convert from Json
                ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
        } else {
            # Output exception
            $Response.Result.EnsureSuccessStatusCode()
        }
    }
}
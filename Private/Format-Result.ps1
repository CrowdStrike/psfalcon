function Format-Result {
<#
.SYNOPSIS
    Formats a response from the Falcon API
.PARAMETER RESPONSE
    Response object from a Falcon API request
.PARAMETER ENDPOINT
    Falcon endpoint
#>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Response,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [string] $Endpoint
    )
    process {
        $Output = if ($Response.Result.Content) {
            if ($Response.Result.Content -match '^<') {
                # Output HTML
                ($Response.Result.Content).ReadAsStringAsync().Result
            } else {
                # Convert from Json
                ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
        }
        if ($Output) {
            # Set TypeName from response
            $TypeName = $Falcon.Endpoint($Endpoint).Responses.($Response.result.StatusCode.GetHashCode())

            if ($TypeName) {
                # Add TypeName to Output
                $Output.PSObject.TypeNames.Insert(0, "$TypeName")
            }
            # Output result
            $Output
        } elseif ($Response.Result) {
            # Output exception
            $Response.Result.EnsureSuccessStatusCode()
        } else {
            # Catch all for unexpected responses
            $Response
        }
    }
}
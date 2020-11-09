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
        [Parameter(Mandatory = $true)]
        [object] $Response,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint
    )
    process {
        $Output = if ($Response.Result.Content) {
            if ($Response.Result.Content -match '^<') {
                ($Response.Result.Content).ReadAsStringAsync().Result
            }
            else {
                ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
        }
        if ($Output) {
            $TypeName = $Falcon.Endpoint($Endpoint).Responses.($Response.result.StatusCode.GetHashCode())
            if ($TypeName) {
                $Output.PSObject.TypeNames.Insert(0, "$TypeName")
            }
            $Output
        }
        elseif ($Response.Result) {
            $Response.Result.EnsureSuccessStatusCode()
        }
        else {
            $Response
        }
    }
}
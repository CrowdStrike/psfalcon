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
    begin {
        $StatusCode = $Response.Result.StatusCode.GetHashCode()
        if ($StatusCode) {
            $Definition = $Falcon.Response($Endpoint, $StatusCode)
            Write-Verbose ("[$($MyInvocation.MyCommand.Name)] $($StatusCode): $Definition")
        }
    }
    process {
        try {
            if ($Response.Result.Content -match '^<') {
                $HTML = ($Response.Result.Content).ReadAsStringAsync().Result
            }
            elseif ($Response.Result.Content) {
                $Json = ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
            }
            if ($Json) {
                Read-Meta -Object $Json -Endpoint $Endpoint
                $Populated = ($Json.PSObject.Properties).foreach{
                    if ($_.Value -and ($_.Name -ne 'meta')) {
                        $_.Name
                    }
                }
                $Output = if ($Populated.count -eq 1) {
                    if ($Populated[0] -eq 'errors') {
                        throw "$($Json.errors.code): $($Json.errors.message)"
                    }
                    else {
                        $Json.($Populated[0])
                    }
                }
                else {
                    $Json
                }
                $Output
            }
            elseif ($HTML) {
                $HTML
            }
            elseif ($Response.Result) {
                $Response.Result.EnsureSuccessStatusCode()
            }
            else {
                $Response
            }
        }
        catch {
            Write-Error $_.Exception.Message
        }
    }
}
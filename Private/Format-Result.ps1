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
        if ($Response.Result.Content -match '^<') {
            $HTML = ($Response.Result.Content).ReadAsStringAsync().Result
        }
        elseif ($Response.Result.Content) {
            $Json = ConvertFrom-Json ($Response.Result.Content).ReadAsStringAsync().Result
        }
        if ($Json) {
            Read-Meta -Object $Json -Endpoint $Endpoint
            $Output = $Json | Select-Object -ExcludeProperty Meta
            $Populated = ($Output.PSObject.Properties).foreach{
                if ($_.Value) {
                    $_.Name
                }
            }
            if ($Populated.count -eq 1) {
                $Output.($Populated[0])
            }
            else {
                if ($Definition) {
                    $Output.PSObject.TypeNames.Insert(0,$Definition)
                }
                $Output
            }
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
}
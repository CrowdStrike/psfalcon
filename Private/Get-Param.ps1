function Get-Param {
    <#
    .SYNOPSIS
        Creates a 'splat' hashtable for Invoke-Endpoint
    .PARAMETER ENDPOINT
        Falcon endpoint name
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    .PARAMETER MAX
        A maximum number of identifiers per request
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic,

        [Parameter()]
        [int] $Max
    )
    begin {
        $Target = $Falcon.Endpoint($Endpoint)
        $Output = @{
            Endpoint = $Endpoint
        }
    }
    process {
        @('Body', 'Formdata', 'Header', 'Outfile', 'Path', 'Query') | ForEach-Object {
            New-Variable -Name $_ -Value (& "Get-$_" -Endpoint $Target -Dynamic $Dynamic)
            if ((Get-Variable $_).Value) {
                $Output[$_] = (Get-Variable $_).Value
            }
        }
        if ($Max) {
            Split-Param -Param $Output -Max $Max
        }
        else {
            Split-Param -Param $Output
        }
    }
}
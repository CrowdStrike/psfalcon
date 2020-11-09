function Get-Header {
    <#
    .SYNOPSIS
        Outputs a hashtable of header values from input
    .PARAMETER ENDPOINT
        Falcon endpoint
    .PARAMETER DYNAMIC
        A runtime parameter dictionary to search for input values
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            if ($Param.In -match 'header') {
                if (-not($HeaderOutput)) {
                    $HeaderOutput = @{ }
                }
                $HeaderOutput[$Param.Name] = $Item.Value
            }
        }
        if ($HeaderOutput) {
            $HeaderOutput
        }
    }
}
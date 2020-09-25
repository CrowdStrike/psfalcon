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
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Endpoint,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            # Match input parameter with endpoint
            $Param = $Endpoint.Parameters | Where-Object Dynamic -eq $Item.Name

            if ($Param.In -match 'header') {
                if (-not($HeaderOutput)) {
                    $HeaderOutput = @{ }
                }
                # Add header key/value to output
                $HeaderOutput[$Param.Name] = $Item.Value
            }
        }
        if ($HeaderOutput) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $(ConvertTo-Json $HeaderOutput)"

            # Output header value
            $HeaderOutput
        }
    }
}
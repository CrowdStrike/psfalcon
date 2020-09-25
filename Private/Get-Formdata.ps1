function Get-Formdata {
<#
.SYNOPSIS
    Outputs a 'Formdata' dictionary from input
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

            if ($Param.In -match 'formdata') {
                if (-not($FormdataOutput)) {
                    $FormdataOutput = @{}
                }
                # Add parameter to output
                $FormdataOutput[$Param.Name] = $Item.Value
            }
        }
        if ($FormdataOutput) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $(ConvertTo-Json $FormdataOutput)"

            # Output formdata value
            $FormdataOutput
        }
    }
}
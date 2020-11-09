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
        [Parameter(Mandatory = $true)]
        [object] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            if ($Param.In -match 'formdata') {
                if (-not($FormdataOutput)) {
                    $FormdataOutput = @{}
                }
                $FormdataOutput[$Param.Name] = $Item.Value
            }
        }
        if ($FormdataOutput) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $(ConvertTo-Json $FormdataOutput)"
            $FormdataOutput
        }
    }
}
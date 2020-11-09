function Get-Path {
    <#
    .SYNOPSIS
        Modifies an endpoint 'path' value based on input
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
    begin {
        $PathOutput = $Endpoint.Path
    }
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            if ($Param.In -match 'path') {
                $PathOutput = $PathOutput.replace(($Param.Name), ($Item.Value))
                $PathModified = $true
            }
        }
        if ($PathModified -eq $true) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $PathOutput"
            $PathOutput
        }
    }
}
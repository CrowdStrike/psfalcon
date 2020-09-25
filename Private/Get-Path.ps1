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
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [object] $Endpoint,

        [Parameter(
            Mandatory = $true,
            Position = 2)]
        [System.Collections.ArrayList] $Dynamic
    )
    begin {
        # Retrieve default endpoint path
        $PathOutput = $Endpoint.Path
    }
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            # Match input parameter with endpoint
            $Param = $Endpoint.Parameters | Where-Object Dynamic -eq $Item.Name

            if ($Param.In -match 'path') {
                # Modify path to include input
                $PathOutput = $PathOutput.replace(($Param.Name), ($Item.Value))

                # Set modified status for debug output
                $PathModified = $true
            }
        }
        if ($PathModified -eq $true) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $PathOutput"

            # Output path value
            $PathOutput
        }
    }
}
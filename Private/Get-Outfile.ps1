function Get-Outfile {
<#
.SYNOPSIS
    Outputs a string from 'outfile' input
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

            $FileOutput = if ($Param.In -match 'outfile') {
                if ($Item.Value -match '^\.') {
                    # Convert relative path to absolute path
                    $Item.Value -replace '^\.', $pwd
                } else {
                    # Output path
                    $Item.Value
                }
            }
        }
        if ($FileOutput) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $FileOutput"

            # Output outfile value
            $FileOutput
        }
    }
}
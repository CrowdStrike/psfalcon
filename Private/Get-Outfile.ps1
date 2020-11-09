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
        [Parameter(Mandatory = $true)]
        [object] $Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList] $Dynamic
    )
    process {
        foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            $FileOutput = if ($Param.In -match 'outfile') {
                if ($Item.Value -match '^\.') {
                    $Item.Value -replace '^\.', $pwd
                }
                else {
                    $Item.Value
                }
            }
        }
        if ($FileOutput) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $FileOutput"
            $FileOutput
        }
    }
}
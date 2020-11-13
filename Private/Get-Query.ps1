function Get-Query {
    <#
    .SYNOPSIS
        Outputs an array of query values from input
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
        if ($Dynamic.Filter.Value) {
            $Hours = "(last (?<Int>\d{1,}) (hour[s]?)){1,}"
            $Days = "(last (?<Int>\d{1,}) (day[s]?)){1,}"
            if ($Dynamic.Filter.Value -match $Hours) {
                $Dynamic.Filter.Value | Select-String $Hours -AllMatches | ForEach-Object {
                    foreach ($Match in $_.Matches.Value) {
                        [int] $Int = $Match -replace $Hours, '${Int}'
                        $Dynamic.Filter.Value = $Dynamic.Filter.Value -replace $Match, $Falcon.Rfc3339(-$Int)
                    }
                }
            }
            if ($Dynamic.Filter.Value -match $Days) {
                $Dynamic.Filter.Value | Select-String $Days -AllMatches | ForEach-Object {
                    foreach ($Match in $_.Matches.Value) {
                        [int] $Int = $Match -replace $Days, '${Int}'
                        $Dynamic.Filter.Value = $Dynamic.Filter.Value -replace $Match, $Falcon.Rfc3339(-24*$Int)
                    }
                }
            }
        }
    }
    process {
        $QueryOutput = foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = if ($Endpoint.Parameters.Dynamic -contains $Item.Name) {
                $Endpoint.Parameters | Where-Object Dynamic -EQ $Item.Name
            }
            else {
                $Falcon.Endpoint('private/SharedParameters').Parameters | Where-Object Dynamic -EQ $Item.Name
            }
            if ($Param.In -match 'query') {
                foreach ($Value in $Item.Value) {
                    if ($Param.Name) {
                        ,"$($Param.Name)=$($Value -replace '\+','%2B')"
                    }
                    else {
                        ,"$($Value -replace '\+','%2B')"
                    }
                    
                }
            }
        }
        if ($QueryOutput) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $($QueryOutput -join ', ')"
            $QueryOutput
        }
    }
}
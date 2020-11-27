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
            $Relative = "(last (?<Int>\d{1,}) (day[s]?|hour[s]?))"
            if ($Dynamic.Filter.Value -match $Relative) {
                $Dynamic.Filter.Value | Select-String $Relative -AllMatches | ForEach-Object {
                    foreach ($Match in $_.Matches.Value) {
                        [int] $Int = $Match -replace $Relative, '${Int}'
                        if ($Match -match "day") {
                            $Int = $Int * -24
                        } else {
                            $Int = $Int * -1
                        }
                        $Dynamic.Filter.Value = $Dynamic.Filter.Value -replace $Match, $Falcon.Rfc3339($Int)
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
            $VerboseOutput = (($QueryOutput).foreach{
                if (($_ -match '^offset=') -and ($_.Length -gt 14)) {
                    "$($_.Substring(0,13))..."
                }
                elseif (($_ -match '^after=') -and ($_.Length -gt 13)) {
                    "$($_.Substring(0,12))..."
                }
                else {
                    $_
                }
            }) -join ', '
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $VerboseOutput"
            $QueryOutput
        }
    }
}
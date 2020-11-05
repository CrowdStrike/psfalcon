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
        if ($Dynamic.Filter.Value) {
            # Convert relative time values into RFC3339 string
            $LastHourValue = if ($Dynamic.Filter.Value -match "\:\'Last (?<StrValue>(hour|day|week))\'") {
                if ($Matches.StrValue -eq 'hour') {
                    -1
                } elseif ($Matches.StrValue -eq 'day') {
                    -24
                } elseif ($Matches.StrValue -eq 'week') {
                    -168
                }
            } elseif ($Dynamic.Filter.Value -match "\:\'Last (?<IntValue>\d{1,}) hours\'") {
                ([int] $Matches.IntValue) * -1
            } elseif ($Dynamic.Filter.Value -match "\:\'Last (?<IntValue>\d{1,}) days\'") {
                ([int] $Matches.IntValue) * -24
            }
            if ($Matches -and $LastHourValue) {
                $Dynamic.Filter.Value = $Dynamic.Filter.Value -replace $Matches[0],
                ":>'$($Falcon.Rfc3339($LastHourValue))'"
            }
        }
    }
    process {
        $QueryOutput = foreach ($Item in ($Dynamic.Values | Where-Object IsSet)) {
            $Param = if ($Endpoint.Parameters.Dynamic -contains $Item.Name) {
                # Match input parameter with endpoint
                $Endpoint.Parameters | Where-Object Dynamic -eq $Item.Name
            } else {
                # Match input with SharedParameters
                $Falcon.Endpoint('private/SharedParameters').Parameters | Where-Object Dynamic -eq $Item.Name
            }
            if ($Param.In -match 'query') {
                foreach ($Value in $Item.Value) {
                    # Output query value
                    if ($Param.Name) {
                        ,"$($Param.Name)=$($Value -replace '\+','%2B')"
                    } else {
                        ,"$($Value -replace '\+','%2B')"
                    }
                    
                }
            }
        }
        if ($QueryOutput) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] $($QueryOutput -join ', ')"

            # Output query value(s)
            $QueryOutput
        }
    }
}
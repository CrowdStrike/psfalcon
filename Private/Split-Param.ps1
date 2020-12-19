function Split-Param {
    <#
    .SYNOPSIS
        Splits 'splat' hashtables into smaller groups to avoid limitations
    .PARAMETER PARAM
        Parameter hashtable
    .PARAMETER MAX
        A maximum number of identifiers per request
    #>
    [CmdletBinding()]
    [OutputType()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Param,

        [Parameter()]
        [int] $Max
    )
    begin {
        if (-not($Max)) {
            $Target = $Falcon.Endpoint($Param.Endpoint)
            $Max = if ($Output.Query -match 'ids=') {
                if ($Falcon.Hostname -match 'api.eu-1.crowdstrike.com') {
                    500
                } else {
                    $PathLength = ("$($Falcon.Hostname)$($Target.Path)").Length
                    $LongestId = (($Output.Query | Where-Object { $_ -match 'ids='}) |
                        Measure-Object -Maximum -Property Length).Maximum + 1
                    $IdCount = [Math]::Floor([decimal]((65535 - $PathLength)/$LongestId))
                    if ($IdCount -gt 1000) {
                        1000
                    }
                    else {
                        $IdCount
                    }
                }
            } elseif (($Target.Parameters | Where-Object Name -eq ids).Max -gt 0) {
                ($Target.Parameters | Where-Object Name -eq ids).Max
            } else {
                $null
            }
        }
    }
    process {
        if ($Max -and $Param.Query.count -gt $Max) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $Max query values per request"
            for ($i = 0; $i -lt $Param.Query.count; $i += $Max) {
                $Group = @{
                    Query = $Param.Query[$i..($i + ($Max - 1))]
                }
                ($Param.Keys).foreach{
                    if ($_ -ne 'Query') {
                        $Group[$_] = $Param.$_
                    }
                }
                $Group
            }
        } elseif ($Max -and $Param.Body.ids.count -gt $Max) {
            Write-Verbose "[$($MyInvocation.MyCommand.Name)] $Max body values per request"
            for ($i = 0; $i -lt $Param.Body.ids.count; $i += $Max) {
                $Group = @{
                    Body = @{
                        ids = $Param.Body.ids[$i..($i + ($Max - 1))]
                    }
                }
                ($Param.Keys).foreach{
                    if ($_ -ne 'Body') {
                        $Group[$_] = $Param.$_
                    } else {
                        (($Param.$_).Keys).foreach{
                            if ($_ -ne 'ids') {
                                $Group.Body[$_] = $Param.Body.$_
                            }
                        }
                    }
                }
                $Group
            }
        } else {
            $Param
        }
    }
}
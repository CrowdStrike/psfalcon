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
        [Parameter(
            Mandatory = $true,
            Position = 1)]
        [hashtable] $Param,

        [Parameter(Position = 2)]
        [int] $Max
    )
    begin {
        if (-not($Max)) {
            $Target = $Falcon.Endpoint($Param.Endpoint)

            $Max = if ($Output.Query -match 'ids=') {
                if ($Falcon.Hostname -match 'api.eu-1.crowdstrike.com') {
                    # Maximum of 500 identifiers per group - API error, Sep 2020
                    500
                } else {
                    # URL length
                    $PathLength = ("$($Falcon.Hostname)$($Target.Path)").Length

                    # Find longest identifier length from input
                    $LongestId = (($Output.Query | Where-Object { $_ -match 'ids='}) |
                        Measure-Object -Maximum -Property Length).Maximum + 1

                    # Set maximum based on projected string length
                    [Math]::Floor([decimal]((65535 - $PathLength)/$LongestId))
                }
            } elseif (($Target.Parameters | Where-Object Name -eq ids).Max -gt 0) {
                # Set maximum from endpoint
                ($Target.Parameters | Where-Object Name -eq ids).Max
            } else {
                $null
            }
        }
    }
    process {
        if ($Max -and $Param.Query.count -gt $Max) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] query: $Max identifiers per request"

            for ($i = 0; $i -lt $Param.Query.count; $i += $Max) {
                # Output groups of 'query' inputs
                $Group = @{
                    Endpoint = $Param.Endpoint
                    Query = $Param.Query[$i..($i + ($Max - 1))]
                }
                @('Body', 'Formdata', 'Header', 'Outfile', 'Path') | ForEach-Object {
                    if ($Param.$_) {
                        # Add other fields to group
                        $Group[$_] = $Param.$_
                    }
                }
                # Output result
                $Group
            }
        } elseif ($Max -and $Param.Body.ids.count -gt $Max) {
            Write-Debug "[$($MyInvocation.MyCommand.Name)] body: $Max identifiers per request"

            for ($i = 0; $i -lt $Param.Body.ids.count; $i += $Max) {
                # Output groups of 'body' inputs
                $Group = @{
                    Endpoint = $Param.Endpoint
                    Body = @{ ids = @( $Param.Body.ids[$i..($i + ($Max - 1))] ) }
                }
                @('Formdata', 'Header', 'Outfile', 'Path', 'Query') | ForEach-Object {
                    if ($Param.$_) {
                        # Add other fields to group
                        $Group[$_] = $Param.$_
                    }
                }
                # Output result
                $Group
            }
        } else {
            # Output without modification
            $Param
        }
    }
}
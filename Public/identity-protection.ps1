function Invoke-FalconIdentityGraph {
<#
.SYNOPSIS
Interact with Falcon Identity using GraphQL
.DESCRIPTION
Requires 'Identity Protection GraphQL: Write'.
.PARAMETER Query
A complete GraphQL query statement
.PARAMETER Type
Query type
.PARAMETER Argument
Parameters and values to restrict result
.PARAMETER Node
Specific properties to return in the result
.PARAMETER All
Repeat requests until all available results are retrieved
#>
    [CmdletBinding(DefaultParameterSetName='Query',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='Query',Mandatory,ValueFromPipeline,Position=1)]
        [string]$Query,
        [Parameter(ParameterSetName='Parameters',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
        [ValidateSet('countEntities','entities','incident','incidents','riskByMembershipSummary','riskFactors',
            'securityAssessment','securityAssessmentGoals','securityAssessmentHistory','timeline',
            IgnoreCase=$false)]
        [string]$Type,
        [Parameter(ParameterSetName='Parameters',ValueFromPipelineByPropertyName,Position=2)]
        [string[]]$Argument,
        [Parameter(ParameterSetName='Parameters',ValueFromPipelineByPropertyName,Position=3)]
        [Alias('nodes')]
        [string[]]$Node,
        [Parameter(ParameterSetName='Parameters')]
        [switch]$All
    )
    begin {
        function Invoke-GraphLoop ($Object,$Inputs,$Command) {
            if ($Object.entities.pageInfo.hasNextPage -eq $true -and $null -ne
            $Object.entities.pageInfo.endCursor) {
                do {
                    [string]$After = 'after:"{0}"' -f $Object.entities.pageInfo.endCursor
                    $Param = @{
                        Type = $Inputs.Type
                        Argument = if ($Inputs.Argument) {
                            if ($Inputs.Argument -match '^after:.*$') {
                                $Inputs.Argument -replace '^after:.*$',$After
                            } else {
                                [string[]]$Inputs.Argument + $After
                            }
                        } else {
                            [string[]]$After
                        }
                        Node = $Inputs.Node
                    }
                    & $Command @Param -All -OutVariable Object
                } until (
                    $Object.entities.pageInfo.hasNextPage -eq $false -or $null -eq
                        $Object.entities.pageInfo.endCursor
                )
            }
        }
        function Write-GraphResult ($Object,$String) {
            if ($Object.$String.pageInfo) {
                [string]$Message = (@($Object.$String.pageInfo.PSObject.Properties).foreach{
                    $_.Name,$_.Value -join '='
                }) -join ', '
                Write-Verbose ('[Invoke-FalconIdentityGraph]',$Message -join ' ')
            }
            if ($Object.$String.nodes) {
                $Object.$String.nodes
            } elseif ($Object.$String) {
                $Object.$String
            } else {
                $Object
            }
        }
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/identity-protection/combined/graphql/v1:post'
            Format = @{ Body = @{ root = @('query') }}
        }
    }
    process {
        $Request = if ($PSCmdlet.ParameterSetName -eq 'Query') {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        } else {
            [string[]]$Query = switch ($PSBoundParameters) {
                { $_.Type } {
                    if ($PSBoundParameters.Argument) {
                        $PSBoundParameters.Type,"($($PSBoundParameters.Argument -join ' '))" -join $null
                    } else {
                        $PSBoundParameters.Type
                    }
                }
                { $_.Node } {
                    [string]$NodeString = if ($PSBoundParameters.Type -eq 'securityAssessment') {
                        '{',($PSBoundParameters.Node -join ' ') -join $null
                    } elseif ($PSBoundParameters.Type -ne 'countEntities') {
                        "{nodes{$($PSBoundParameters.Node -join ' ')}"
                    }
                    if ($NodeString) {
                        if ($PSBoundParameters.All -and $PSBoundParameters.Type -eq 'entities') {
                            $NodeString = $NodeString,'pageInfo{hasNextPage endCursor}' -join ' '
                        }
                        $NodeString,'}' -join $null
                    }
                }
            }
            & $MyInvocation.MyCommand.Name -Query "{$($Query -join ' ')}"
        }
    }
    end {
        if ($Request) {
            if ($Type) {
                Write-GraphResult $Request $Type
                if ($PSBoundParameters.All -and $PSBoundParameters.Node) {
                    Invoke-GraphLoop $Request $PSBoundParameters $Param.Command
                }
            } else {
                $Request
            }
        }
    }
}
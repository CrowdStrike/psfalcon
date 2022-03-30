function Invoke-FalconIdentityGraph {
<#
.SYNOPSIS
Interact with Falcon Identity using GraphQL
.DESCRIPTION
Requires 'Identity Protection GraphQL: Write'.
.PARAMETER Query
GraphQL query statement
#>
    [CmdletBinding(DefaultParameterSetName='/identity-protection/combined/graphql/v1:post')]
    param(
        [Parameter(ParameterSetName='/identity-protection/combined/graphql/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [string]$Query
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('query') }}
        }
    }
    process {
        Invoke-Falcon @Param -Inputs $PSBoundParameters
        <#
        $Param = @{
            Path = "$($Script:Falcon.Hostname)/identity-protection/combined/graphql/v1"
            Method = 'post'
            Headers = @{
                Accept = 'application/json'
                ContentType = 'application/json'
            }
            Body = ConvertTo-Json -InputObject @{ query = "{$($PSBoundParameters.Query)}" } -Compress
        }
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result -Request $Request
        #>
    }
}
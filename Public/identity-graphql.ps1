function Invoke-FalconIdentityGraph {
    [CmdletBinding(DefaultParameterSetName = '/identity-protection/combined/graphql/v1:post')]
    param(
        [Parameter(ParameterSetName = '/identity-protection/combined/graphql/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Query
    )
    begin {
        if (!$Script:Falcon.Hostname) { Request-FalconToken }
    }
    process {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/identity-protection/combined/graphql/v1"
            Method  = 'post'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body = ConvertTo-Json -InputObject @{ query = "{$($PSBoundParameters.Query)}" } -Compress
        }
        $Request = $Script:Falcon.Api.Invoke($Param)
        Write-Result -Request $Request
    }
}
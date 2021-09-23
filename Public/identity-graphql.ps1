function Invoke-FalconIdentityGraph {
<#
.Synopsis
Interact with Falcon Identity using GraphQL
.Description
Requires 'identity-graphql:write'.
.Parameter Query
GraphQL query statement
.Example
PS>Invoke-FalconIdentityGraph -Query 'entities(roles:[BuiltinAdministratorRole] sortKey:PRIMARY_DISPLAY_NAME
sortOrder:ASCENDING first:5) {nodes{primaryDisplayName secondaryDisplayName}}'

Query the primary and secondary display names for the first 5 Administrator accounts, sorted in ascending order
by primary display name.
.Example
PS>Invoke-FalconIdentityGraph -Query 'entities(types:[USER] minRiskScoreSeverity:MEDIUM sortKey:
RISK_SCORE sortOrder:DESCENDING first:10) {nodes{primaryDisplayName secondaryDisplayName isHuman:hasRole(
type:HumanUserAccountRole) isProgrammatic:hasRole(type:ProgrammaticUserAccountRole) ... on UserEntity{
emailAddresses} riskScore riskScoreSeverity riskFactors {type severity}}}'

Query the top 10 users with the highest risk score and display basic information about their accounts and
the risk factors contributing to their score.
#>
    [CmdletBinding(DefaultParameterSetName = '/identity-protection/combined/graphql/v1:post')]
    param(
        [Parameter(ParameterSetName = '/identity-protection/combined/graphql/v1:post', Mandatory = $true,
            Position = 1)]
        [string] $Query
    )
    begin {
        $Param = @{
            Path    = "$($Script:Falcon.Hostname)/identity-protection/combined/graphql/v1"
            Method  = 'post'
            Headers = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Body = ConvertTo-Json -InputObject @{ query = "{$($PSBoundParameters.Query)}" } -Compress 
        }
    }
    process {
        Write-Result ($Script:Falcon.Api.Invoke($Param))
    }
}
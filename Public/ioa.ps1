function Get-FalconHorizonIoaEvent {
<#
.Synopsis
For CSPM IOA events, gets list of IOA events.
.Parameter CloudPlatform
Cloud platform
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter UserIds
One or more user identifiers
.Parameter AccountId
Cloud account identifier
.Parameter AzureTenantId
Azure tenant identifier
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioa/entities/events/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\d{*}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Position = 3)]
        [array] $UserIds,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Position = 4)]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Position = 5)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $AzureTenantId,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Position = 6)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Position = 7)]
        [int] $Offset
    )
    begin {
        $Fields = @{
            AccountId     = 'account_id'
            AzureTenantId = 'azure_tenant_id'
            CloudPlatform = 'cloud_provider'
            PolicyId      = 'policy_id'
            UserIds       = 'user_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('cloud_provider', 'limit', 'account_id', 'policy_id', 'offset',
                    'azure_tenant_id', 'user_ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonIoaUser {
<#
.Synopsis
For CSPM IOA users, gets list of IOA users.
.Parameter CloudPlatform
Cloud platform
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter AccountId
Cloud account identifier
.Parameter AzureTenantId
Azure tenant identifier
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioa/entities/users/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\d{*}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Position = 3)]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Position = 4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $AzureTenantId
    )
    begin {
        $Fields = @{
            AccountId     = 'account_id'
            AzureTenantId = 'azure_tenant_id'
            CloudPlatform = 'cloud_provider'
            PolicyId      = 'policy_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('cloud_provider', 'policy_id', 'azure_tenant_id', 'account_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
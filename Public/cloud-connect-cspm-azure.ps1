function Edit-FalconDefaultSubscriptionId {
<#
.Synopsis
Update an Azure default subscription_id in our system for given tenant_id
.Parameter TenantId

.Parameter SubscriptionId

.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch')]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $TenantId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch', Mandatory = $true)]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $SubscriptionId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{Query = @('tenant-id', 'subscription_id')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconAccount {
<#
.Synopsis
Deletes an Azure subscription from the system.
.Parameter Ids
One or more XXX identifiers
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:delete', Mandatory = $true)]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{Query = @('ids')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserScriptsDownload {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment
.Parameter TenantId

.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $TenantId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json application/octet-stream'}
            Format   = @{Query = @('tenant-id')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconClientId {
<#
.Synopsis
Update an Azure service account in our system by with the user-created client_id created with the public key weve provided
.Parameter TenantId

.Parameter Id
XXX identifier
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/client-id/v1:patch')]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $TenantId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/client-id/v1:patch', Mandatory = $true)]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $Id
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{Query = @('tenant-id', 'id')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconAccount {
<#
.Synopsis
Return information about Azure account registration
.Parameter ScanType

.Parameter Offset
Position to begin retrieving results
.Parameter Ids
One or more XXX identifiers
.Parameter Status

.Parameter Limit
Maximum number of results per request
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [ValidateSet('full', 'dry')]
        [ValidateLength(3, 4)]
        [string] $ScanType,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [ValidateRange(1, 3)]
        [int] $Limit
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{Query = @('scan-type', 'offset', 'ids', 'status', 'limit')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconAccount {
<#
.Synopsis
Creates a new account in our system for a customer and generates a script for them to run in their cloud environment to grant us access.
.Parameter SubscriptionId

.Parameter TenantId

.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:post')]
        [string] $SubscriptionId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:post')]
        [string] $TenantId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{;Body = @{resources = @('subscription_id', 'tenant_id')}}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}

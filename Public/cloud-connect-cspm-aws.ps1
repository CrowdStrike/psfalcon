function Remove-FalconAccount {
<#
.Synopsis
Deletes an existing AWS account or organization in our system.
.Parameter Ids
One or more XXX identifiers
.Parameter OrganizationIds

.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:delete')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:delete')]
        [array] $OrganizationIds
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{Query = @('ids', 'organization-ids')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserScriptsDownload {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their AWS environment as a downloadable attachment.

.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json application/octet-stream'}
            Format   = @{Query = @('ids', 'organization-ids')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconAccount {
<#
.Synopsis
Patches a existing account in our system for a customer.
.Parameter AccountId

.Parameter CloudtrailRegion

.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:patch', Mandatory = $true)]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:patch', Mandatory = $true)]
        [string] $CloudtrailRegion
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{;Body = @{resources = @('account_id', 'cloudtrail_region')}}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconConsoleSetupUrls {
<#
.Synopsis
Return a URL for customer to visit in their cloud environment to grant us access to their AWS environment.

.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{;Body = @{resources = @('account_id', 'cloudtrail_region')}}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconAccount {
<#
.Synopsis
Returns information about the current status of an AWS account.
.Parameter Limit
Maximum number of results per request
.Parameter Ids
One or more XXX identifiers
.Parameter OrganizationIds

.Parameter ScanType

.Parameter Offset
Position to begin retrieving results
.Parameter GroupBy

.Parameter Status

.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [ValidateRange(1, 3)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [array] $OrganizationIds,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [ValidateSet('full', 'dry')]
        [ValidateLength(3, 4)]
        [string] $ScanType,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [ValidateSet('organization')]
        [string] $GroupBy,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{Query = @('limit', 'ids', 'organization-ids', 'scan-type', 'offset', 'group_by', 'status')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconAccount {
<#
.Synopsis
Creates a new account in our system for a customer and generates a script for them to run in their AWS cloud environment to grant us access.
.Parameter CloudtrailRegion

.Parameter AccountId

.Parameter OrganizationId

.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Mandatory = $true)]
        [string] $CloudtrailRegion,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Mandatory = $true)]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Mandatory = $true)]
        [string] $OrganizationId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{Accept = 'application/json';ContentType = 'application/json'}
            Format   = @{;Body = @{resources = @('cloudtrail_region', 'account_id', 'organization_id')}}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}

function Edit-FalconHorizonAwsAccount {
<#
.Synopsis
Modify a Falcon Horizon AWS account
.Parameter AccountId
AWS account identifier
.Parameter CloudtrailRegion
AWS region where the account resides
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:patch', Position = 2)]
        [string] $CloudtrailRegion
    )
    begin {
        $Fields = @{
            AccountId        = 'account_id'
            CloudtrailRegion = 'cloudtrail_region'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('account_id', 'cloudtrail_region')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonAzureAccount {
<#
.Synopsis
Modify the Falcon Horizon Azure default client or subscription identifier
.Parameter Id
Azure client identifier
.Parameter SubscriptionId
Azure subscription identifier
.Parameter TenantId
Azure tenant identifier, required when multiple tenants have been registered
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/client-id/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
                Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SubscriptionId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/client-id/v1:patch', Position = 2)]
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
            Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $TenantId
    )
    begin {
        $Fields = @{
            SubscriptionId = 'subscription_id'
            TenantId       = 'tenant-id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('tenant-id', 'id', 'subscription_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconDefaultSubscriptionId {
    <#
    .Synopsis
    Modify Falcon Horizon Azure accounts
    .Parameter SubscriptionId
    Default subscription identifier for all subscriptions within a tenant
    .Parameter TenantId
    Azure tenant identifier
    .Role
    cspm-registration:write
    #>
        [CmdletBinding(
            DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch')]
        param(
            [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
                Mandatory = $true, Position = 1)]
            [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
            [string] $SubscriptionId,
    
            [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
                Position = 2)]
            [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
            [string] $TenantId
        )
        begin {
            $Fields = @{
                SubscriptionId = 'subscription_id'
                TenantId       = 'tenant-id'
            }
            $Param = @{
                Command  = $MyInvocation.MyCommand.Name
                Endpoint = $PSCmdlet.ParameterSetName
                Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
                Format   = @{
                    Query = @('tenant-id', 'subscription_id')
                }
            }
        }
        process {
            Invoke-Falcon @Param
        }
    }
function Edit-FalconHorizonPolicy {
<#
.Synopsis
Updates a policy setting - can be used to override policy severity or to disable a policy entirely.
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter Enabled
Policy enablement status
.Parameter Severity
Severity level
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/entities/policy/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 1)]
        [int32] $PolicyId,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 2)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:patch', Mandatory = $true, Position = 3)]
        [ValidateSet('informational', 'medium', 'high')]
        [string] $Severity
    )
    begin {
        $Fields = @{
            PolicyId = 'policy_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('severity', 'policy_id', 'enabled')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonSchedule {
<#
.Synopsis
Updates Falcon Horizon scan schedule configuration for one or more cloud platforms.
.Parameter CloudPlatform
Cloud platform
.Parameter ScanSchedule
Scan interval
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/scan-schedule/v1:post')]
    param(
        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:post', Mandatory = $true, Position = 2)]
        [ValidateSet('2h', '6h', '12h', '24h')]
        [string] $ScanSchedule
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud_platform'
            ScanSchedule  = 'scan_schedule'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('cloud_platform', 'scan_schedule')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonAwsAccount {
<#
.Synopsis
Search for Falcon Horizon AWS accounts
.Parameter Ids
AWS account identifier(s)
.Parameter OrganizationIds
AWS organization identifier(s)
.Parameter ScanType
Scan type
.Parameter Status
AWS account status
.Parameter GroupBy
Field to group by
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 2)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [array] $OrganizationIds,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 3)]
        [ValidateSet('full', 'dry')]
        [string] $ScanType,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 4)]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 5)]
        [ValidateSet('organization')]
        [string] $GroupBy,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 6)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get', Position = 7)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            GroupBy         = 'group_by'
            OrganizationIds = 'organization-ids'
            ScanType        = 'scan-type'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'organization-ids', 'scan-type', 'offset', 'group_by', 'status')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonAwsLink {
<#
.Synopsis
Retrieve a URL that will grant access for Falcon Horizon in AWS
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/console-setup-urls/v1:get')]
    param()
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonAzureAccount {
<#
.Synopsis
Search for Falcon Horizon Azure accounts
.Parameter Ids
Azure account identifier(s)
.Parameter ScanType
Scan type
.Parameter Status
Azure account status
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get', Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get', Position = 2)]
        [ValidateSet('full', 'dry')]
        [string] $ScanType,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get', Position = 3)]
        [ValidateSet('provisioned', 'operational')]
        [string] $Status,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            ScanType        = 'scan-type'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('scan-type', 'offset', 'ids', 'status', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
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
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
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
        [int] $Offset,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get')]
        [switch] $Total
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
            Format   = @{
                Query = @('cloud_provider', 'policy_id', 'azure_tenant_id', 'account_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonPolicy {
<#
.Synopsis
Returns information about current Falcon Horizon policy settings.
.Parameter Ids
One or more Falcon Horizon policy identifiers
.Parameter PolicyId
Falcon Horizon policy identifier
.Parameter Service
Cloud service type
.Parameter CloudPlatform
Cloud platform
.Parameter Detailed
Retrieve detailed information
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/entities/policy/v1:get')]
    param(
        [Parameter(ParameterSetName = '/settings/entities/policy-details/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{*}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 1)]
        [ValidatePattern('^\d{*}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 2)]
        [ValidateSet('EC2', 'IAM', 'KMS', 'ACM', 'ELB', 'NLB/ALB', 'EBS', 'RDS', 'S3', 'Redshift',
            'NetworkSecurityGroup', 'VirtualNetwork', 'Disk', 'PostgreSQL', 'AppService', 'KeyVault',
            'VirtualMachine', 'Monitor', 'StorageAccount', 'LoadBalancer', 'SQLServer')]
        [string] $Service,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 3)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get')]
        [switch] $Detailed
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud-platform'
            PolicyId      = 'policy-id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'service', 'policy-id', 'cloud-platform')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonSchedule {
<#
.Synopsis
Returns Falcon Horizon scan schedule configuration for one or more cloud platforms.
.Parameter CloudPlatform
Cloud platform
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/settings/scan-schedule/v1:get')]
    param(
        [Parameter(ParameterSetName = '/settings/scan-schedule/v1:get', Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [array] $CloudPlatform
    )
    begin {
        $Fields = @{
            CloudPlatform = 'cloud-platform'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud-platform')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconHorizonAwsAccount {
<#
.Synopsis
Provision a Falcon Horizon AWS account
.Parameter AccountId
AWS account identifier
.Parameter OrganizationId
AWS organization identifier
.Parameter CloudtrailRegion
AWS region where the account resides
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post')]
    param(
        

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $AccountId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Position = 2)]
        [ValidatePattern('^\d{12}$')]
        [string] $OrganizationId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:post', Position = 3)]
        [string] $CloudtrailRegion
    )
    begin {
        $Fields = @{
            AccountId        = 'account_id'
            CloudtrailRegion = 'cloudtrail_region'
            OrganizationId   = 'organization_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('cloudtrail_region', 'account_id', 'organization_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconHorizonAzureAccount {
<#
.Synopsis
Provision Falcon Horizon Azure accounts
.Parameter SubscriptionId
Azure subscription identifier
.Parameter TenantId
Azure tenant identifier
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:post', Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SubscriptionId,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:post', Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $TenantId
    )
    begin {
        $Fields = @{
            SubscriptionId = 'subscription_id'
            TenantId       = 'tenant_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('subscription_id', 'tenant_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconHorizonAwsScript {
<#
.Synopsis
Download a Bash script which grants Falcon Horizon access using AWS CLI
.Parameter Path
Destination path
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^*\.sh$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconHorizonAzureScript {
<#
.Synopsis
Download a Bash script which grants Falcon Horizon access using Azure Cloud Shell
.Parameter TenantId
Azure tenant identifier
.Role
cspm-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^*\.sh$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
            Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $TenantId
    )
    begin {
        $Fields = @{
            TenantId = 'tenant-id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Query   = @('tenant-id')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconHorizonAwsAccount {
<#
.Synopsis
Remove Falcon Horizon AWS accounts
.Parameter Ids
AWS account identifier(s)
.Parameter OrganizationIds
AWS organization identifier(s)
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:delete', Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-cspm-aws/entities/account/v1:delete', Position = 2)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [array] $OrganizationIds
    )
    begin {
        $Fields = @{
            OrganizationIds = 'organization-ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'organization-ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconHorizonAzureAccount {
<#
.Synopsis
Remove Falcon Horizon Azure accounts
.Parameter Ids
Azure account identifier(s)
.Role
cspm-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:delete', Mandatory = $true)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
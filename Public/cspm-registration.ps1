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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids', 'organization-ids')
            }
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
            Headers  = @{
                Accept = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids', 'organization-ids')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('limit', 'ids', 'organization-ids', 'scan-type', 'offset', 'group_by', 'status')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
    [CmdletBinding(DefaultParameterSetName = '')]
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('cloud-platform')
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
            Format   = @{
                Query = @('tenant-id', 'subscription_id')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids')
            }
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
            Headers  = @{
                Accept = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('tenant-id')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('tenant-id', 'id')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('scan-type', 'offset', 'ids', 'status', 'limit')
            }
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
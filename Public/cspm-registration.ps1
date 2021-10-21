function Edit-FalconHorizonAwsAccount {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonAzureAccount {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('tenant-id', 'id', 'subscription_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonPolicy {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Edit-FalconHorizonSchedule {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonAwsAccount {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'organization-ids', 'scan-type', 'offset', 'group_by', 'status')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonAwsLink {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-aws/entities/console-setup-urls/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function Get-FalconHorizonAzureAccount {
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
            ScanType = 'scan-type'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('scan-type', 'offset', 'ids', 'status', 'limit')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonIoaEvent {
    [CmdletBinding(DefaultParameterSetName = '/ioa/entities/events/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/ioa/entities/events/v1:get', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\d+$')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_provider', 'limit', 'account_id', 'policy_id', 'offset',
                    'azure_tenant_id', 'user_ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonIoaUser {
    [CmdletBinding(DefaultParameterSetName = '/ioa/entities/users/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('aws', 'azure', 'gcp')]
        [string] $CloudPlatform,

        [Parameter(ParameterSetName = '/ioa/entities/users/v1:get', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\d+$')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud_provider', 'policy_id', 'azure_tenant_id', 'account_id')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonPolicy {
    [CmdletBinding(DefaultParameterSetName = '/settings/entities/policy/v1:get')]
    param(
        [Parameter(ParameterSetName = '/settings/entities/policy-details/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 1)]
        [ValidatePattern('^\d+$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/settings/entities/policy/v1:get', Position = 2)]
        [ValidateSet('ACM', 'ACR', 'AppService', 'CloudFormation', 'CloudTrail', 'CloudWatch Logs', 'Cloudfront',
            'Config', 'Disk', 'DynamoDB', 'EBS', 'EC2', 'ECR', 'EFS', 'EKS', 'ELB', 'EMR', 'Elasticache',
            'GuardDuty', 'IAM', 'Identity', 'KMS', 'KeyVault', 'Kinesis', 'Kubernetes', 'Lambda', 'LoadBalancer',
            'Monitor', 'NLB/ALB', 'NetworkSecurityGroup', 'PostgreSQL', 'RDS', 'Redshift', 'S3', 'SES', 'SNS',
            'SQLDatabase', 'SQLServer', 'SQS', 'SSM', 'Serverless Application Repository', 'StorageAccount',
            'Subscriptions', 'VirtualMachine', 'VirtualNetwork', IgnoreCase = $false)]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'service', 'policy-id', 'cloud-platform')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHorizonSchedule {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cloud-platform')
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconHorizonAwsAccount {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function New-FalconHorizonAzureAccount {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Receive-FalconHorizonAwsScript {
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
    process {
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
        Invoke-Falcon @Param
    }
}
function Receive-FalconHorizonAzureScript {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Remove-FalconHorizonAwsAccount {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'organization-ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconHorizonAzureAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-cspm-azure/entities/account/v1:delete', Mandatory = $true)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}
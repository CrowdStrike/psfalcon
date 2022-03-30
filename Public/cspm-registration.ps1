function Edit-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Modify a Falcon Horizon AWS account
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER AccountId
AWS account identifier
.PARAMETER CloudtrailRegion
AWS region where the account resides
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('account_id','id')]
        [string]$AccountId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:patch',Position=2)]
        [Alias('cloudtrail_region')]
        [string]$CloudtrailRegion
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('account_id','cloudtrail_region') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Edit-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Modify the default Falcon Horizon Azure client or subscription identifier
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER Id
Azure client identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier, required when multiple tenants have been registered
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
            Mandatory)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',Position=2)]
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
           Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('tenant-id')]
        [string]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('tenant-id','id','subscription_id') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Edit-FalconHorizonPolicy {
<#
.SYNOPSIS
Modify a Falcon Horizon policy
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER Severity
Severity level
.PARAMETER Enabled
Policy enablement status
.PARAMETER PolicyId
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/settings/entities/policy/v1:patch')]
    param(
        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,Position=1)]
        [ValidateSet('informational','medium','high',IgnoreCase=$false)]
        [string]$Severity,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,Position=2)]
        [boolean]$Enabled,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('policy_id')]
        [int32]$PolicyId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('severity','policy_id','enabled') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Edit-FalconHorizonSchedule {
<#
.SYNOPSIS
Modify Falcon Horizon scan schedules
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER ScanSchedule
Scan interval
.PARAMETER CloudPlatform
Cloud platform
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/settings/scan-schedule/v1:post')]
    param(
        [Parameter(ParameterSetName='/settings/scan-schedule/v1:post',Mandatory,Position=1)]
        [ValidateSet('2h','6h','12h','24h',IgnoreCase=$false)]
        [Alias('scan_schedule')]
        [string]$ScanSchedule,

        [Parameter(ParameterSetName='/settings/scan-schedule/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_platform','cloud_provider')]
        [string]$CloudPlatform
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('cloud_platform','scan_schedule') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Search for Falcon Horizon AWS accounts
.DESCRIPTION
Requires 'CSPM Registration: Read'.

A properly provisioned AWS account will display the status 'Event_DiscoverAccountStatusOperational'.
.PARAMETER Id
AWS account identifier
.PARAMETER OrganizationIds
AWS organization identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
AWS account status
.PARAMETER GroupBy
Field to group by
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=2)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [Alias('organization-ids','OrganizationIds')]
        [string[]]$OrganizationId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=3)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=4)]
        [ValidateSet('provisioned','operational',IgnoreCase=$false)]
        [string]$Status,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=5)]
        [ValidateSet('organization',IgnoreCase=$false)]
        [Alias('group_by')]
        [string]$GroupBy,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=6)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get',Position=7)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('limit','ids','organization-ids','scan-type','offset','group_by','status')
            }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconHorizonAwsLink {
<#
.SYNOPSIS
Retrieve a URL to grant Falcon Horizon access in AWS
.DESCRIPTION
Requires 'CSPM Registration: Read'.

Once logging in to the provided link using your AWS administrator credentials, use the 'Create Stack' button to
grant access.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/console-setup-urls/v1:get')]
    param()
    process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}
function Get-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Search for Falcon Horizon Azure accounts
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Id
Azure account identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
Azure account status
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=2)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=3)]
        [ValidateSet('provisioned','operational',IgnoreCase=$false)]
        [string]$Status,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=4)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=5)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('scan-type','offset','ids','status','limit') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconHorizonIoa {
<#
.SYNOPSIS
Search for Falcon Horizon Indicators of Attack
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.PARAMETER Severity
Indicator of Attack severity
.PARAMETER Region
Cloud platform region
.PARAMETER Service
Cloud service
.PARAMETER State
Indicator of Attack state
.PARAMETER DateTimeSince
Include results that occur after a specific date and time (RFC3339)
.PARAMETER Limit
Maximum number of results per request
.PARAMETER NextToken
Pagination token to retrieve the next set of results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/ioa/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id')]
        [string]$AwsAccountId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_tenant_id')]
        [string]$AzureTenantId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=5)]
        [ValidateSet('High','Medium','Informational',IgnoreCase=$false)]
        [string]$Severity,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=6)]
        [string]$Region,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=7)]
        [ValidateSet('ACM','ACR','Any','App Engine','AppService','BigQuery','Cloud Load Balancing',
            'Cloud Logging','Cloud SQL','Cloud Storage','CloudFormation','CloudTrail','CloudWatch Logs',
            'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS',
            'ELB','EMR','Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis',
            'Kubernetes','Lambda','LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL',
            'RDS','Redshift','S3','SES','SNS','SQLDatabase','SQLServer','SQS','SSM',
            'Serverless Application Repository','StorageAccount','Subscriptions','VPC','VirtualMachine',
            'VirtualNetwork',IgnoreCase=$false)]
        [string]$Service,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=8)]
        [ValidateSet('open','closed',IgnoreCase=$false)]
        [string]$State,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=9)]
        [Alias('date_time_since')]
        [string]$DateTimeSince,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=10)]
        [ValidateRange(1,5000)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=11)]
        [Alias('next_token')]
        [string]$NextToken,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('cloud_provider','limit','date_time_since','azure_tenant_id','next_token',
                    'severity','service','state','region','azure_subscription_id','aws_account_id')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonIoaEvent {
<#
.SYNOPSIS
Search for Falcon Horizon Indicator of Attack events
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER PolicyId
Policy identifier
.PARAMETER UserIds
User identifier
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/ioa/entities/events/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=2)]
        [ValidatePattern('^\d+$')]
        [Alias('policy_id')]
        [int32]$PolicyId,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=3)]
        [Alias('user_ids')]
        [string[]]$UserIds,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=4)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id')]
        [string]$AwsAccountId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=5)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=6)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_tenant_id')]
        [string]$AzureTenantId,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=7)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=8)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/ioa/entities/events/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('cloud_provider','limit','aws_account_id','azure_subscription_id','policy_id',
                    'offset','azure_tenant_id','user_ids')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonIoaUser {
<#
.SYNOPSIS
Search for Falcon Horizon Indicator of Attack users
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER PolicyId
Policy identifier
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/ioa/entities/users/v1:get')]
    param(
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,

        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=2)]
        [ValidatePattern('^\d+$')]
        [Alias('policy_id')]
        [int32]$PolicyId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id')]
        [string]$AwsAccountId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,

        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=5)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_tenant_id')]
        [string]$AzureTenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('cloud_provider','policy_id','azure_tenant_id','aws_account_id',
                    'azure_subscription_id')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonIom {
<#
.SYNOPSIS
Search for Falcon Horizon Indicators of Misconfiguration
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER AccountId
AWS account or GCP Project identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.PARAMETER Severity
Indicator of Attack severity
.PARAMETER Region
Cloud platform region
.PARAMETER Service
Cloud service
.PARAMETER State
Indicator of Attack state
.PARAMETER DateTimeSince
Include results that occur after a specific date and time (RFC3339)
.PARAMETER Limit
Maximum number of results per request
.PARAMETER NextToken
Pagination token to retrieve the next set of results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/iom/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=2)]
        [ValidatePattern('^(\d{12}|\w{6,30})$')]
        [Alias('account_id')]
        [string]$AccountId,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=4)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('azure_tenant_id')]
        [string]$AzureTenantId,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=5)]
        [ValidateSet('new','reoccurring','all',IgnoreCase=$false)]
        [string]$Status,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=6)]
        [string]$Region,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=7)]
        [ValidateSet('High','Medium','Informational',IgnoreCase=$false)]
        [string]$Severity,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=8)]
        [ValidateSet('ACM','ACR','Any','App Engine','AppService','BigQuery','Cloud Load Balancing',
            'Cloud Logging','Cloud SQL','Cloud Storage','CloudFormation','CloudTrail','CloudWatch Logs',
            'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS',
            'ELB','EMR','Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis',
            'Kubernetes','Lambda','LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL',
            'RDS','Redshift','S3','SES','SNS','SQLDatabase','SQLServer','SQS','SSM',
            'Serverless Application Repository','StorageAccount','Subscriptions','VPC','VirtualMachine',
            'VirtualNetwork',IgnoreCase=$false)]
        [string]$Service,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=9)]
        [ValidateRange(1,5000)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=10)]
        [Alias('next_token')]
        [string]$NextToken,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/detects/entities/iom/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('cloud_provider','limit','azure_tenant_id','next_token','severity','service',
                    'status','azure_subscription_id','region','aws_account_id')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconHorizonPolicy {
<#
.SYNOPSIS
Retrieve detailed information about Falcon Horizon policies
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Id
Policy identifier
.PARAMETER PolicyId
Policy identifier
.PARAMETER Service
Cloud service type
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER Detailed
Retrieve detailed information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/settings/entities/policy/v1:get')]
    param(
        [Parameter(ParameterSetName='/settings/entities/policy-details/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Mandatory)]
        [ValidatePattern('^\d+$')]
        [Alias('policy_id','ids')]
        [int32[]]$Id,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:get',Position=1)]
        [ValidatePattern('^\d+$')]
        [Alias('policy-id')]
        [int32]$PolicyId,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:get',Position=2)]
        [ValidateSet('ACM','ACR','Any','App Engine','AppService','BigQuery','Cloud Load Balancing',
            'Cloud Logging','Cloud SQL','Cloud Storage','CloudFormation','CloudTrail','CloudWatch Logs',
            'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS',
            'ELB','EMR','Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis',
            'Kubernetes','Lambda','LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL',
            'RDS','Redshift','S3','SES','SNS','SQLDatabase','SQLServer','SQS','SSM',
            'Serverless Application Repository','StorageAccount','Subscriptions','VPC','VirtualMachine',
            'VirtualNetwork',IgnoreCase=$false)]
        [string]$Service,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:get',Position=3)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud-platform')]
        [string]$CloudPlatform,

        [Parameter(ParameterSetName='/settings/entities/policy/v1:get')]
        [switch]$Detailed
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','service','policy-id','cloud-platform') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconHorizonSchedule {
<#
.SYNOPSIS
Retrieve detailed information about Falcon Horizon schedules
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/settings/scan-schedule/v1:get')]
    param(
        [Parameter(ParameterSetName='/settings/scan-schedule/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud-platform','cloud_platform','cloud_provider')]
        [string[]]$CloudPlatform
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('cloud-platform') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process {
        if ($CloudPlatform) { @($CloudPlatform).foreach{ [void]$IdArray.Add($_) }}
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['CloudPlatform'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function New-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Provision a Falcon Horizon AWS account
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER CloudtrailRegion
AWS region where the account resides
.PARAMETER AccountId
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('account_id')]
        [string]$AccountId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('organization_id')]
        [string]$OrganizationId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('cloudtrail_region')]
        [string]$CloudtrailRegion
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('cloudtrail_region','account_id','organization_id') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function New-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Provision a Falcon Horizon Azure account
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('subscription_id')]
        [string]$SubscriptionId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('tenant_id')]
        [string]$TenantId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('subscription_id','tenant_id') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Receive-FalconHorizonAwsScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Horizon access using the AWS CLI
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get',Mandatory,
            Position=1)]
        [string]$Path,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{ Outfile = 'path' }
        }
    }
    process {
        $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'sh'
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Receive-FalconHorizonAzureScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Horizon access using Azure Cloud Shell
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Mandatory,
            Position=1)]
        [string]$Path,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('tenant-id','tenant_id')]
        [string]$TenantId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{
                Query = @('tenant-id')
                Outfile = 'path'
            }
        }
    }
    process {
        $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path 'sh'
        $OutPath = Test-OutFile $PSBoundParameters.Path
        if ($OutPath.Category -eq 'ObjectNotFound') {
            Write-Error @OutPath
        } elseif ($PSBoundParameters.Path) {
            if ($OutPath.Category -eq 'WriteError' -and !$Force) {
                Write-Error @OutPath
            } else {
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Remove-FalconHorizonAwsAccount {
<#
.SYNOPSIS
Remove Falcon Horizon AWS accounts
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:delete')]
    param(
        [Parameter(ParameterSetName='OrganizationIds',Mandatory)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [Alias('organization-ids','OrganizationIds')]
        [string[]]$OrganizationId,

        [Parameter(ParameterSetName='/cloud-connect-cspm-aws/entities/account/v1:delete',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/cloud-connect-cspm-aws/entities/account/v1:delete'
            Format = @{ Query = @('ids','organization-ids') }
        }
        [System.Collections.ArrayList]$IdArray = @()

    }
    process {
        if ($Id) {
            @($Id).foreach{ [void]$IdArray.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Remove-FalconHorizonAzureAccount {
<#
.SYNOPSIS
Remove Falcon Horizon Azure accounts
.DESCRIPTION
Requires 'CSPM Registration: Write'.
.PARAMETER Id
Azure account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Horizon
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.ArrayList]$IdArray = @()
    }
    process { if ($Id) { @($Id).foreach{ [void]$IdArray.Add($_) }}}
    end {
        if ($IdArray) {
            $PSBoundParameters['Id'] = @($IdArray | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
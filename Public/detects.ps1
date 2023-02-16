function Edit-FalconDetection {
<#
.SYNOPSIS
Modify detections
.DESCRIPTION
Requires 'Detections: Write'.
.PARAMETER Comment
Detection comment
.PARAMETER ShowInUi
Visible within the Falcon UI [default: $true]
.PARAMETER Status
Detection status
.PARAMETER AssignedToUuid
User identifier for assignment
.PARAMETER Id
Detection identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDetection
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/detects/v2:patch',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Meta.Response',ParameterSetName='/detects/entities/detects/v2:patch')]
    param(
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Position=2)]
        [Alias('show_in_ui')]
        [boolean]$ShowInUi,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',ValueFromPipelineByPropertyName,
            Position=3)]
        [ValidateSet('new','in_progress','true_positive','false_positive','closed','reopened',IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',ValueFromPipelineByPropertyName,
           Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('assigned_to_uuid','uuid')]
        [string]$AssignedToUuid,
        [Parameter(ParameterSetName='/detects/entities/detects/v2:patch',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=5)]
        [ValidatePattern('^ldt:[a-fA-F0-9]{32}:\d+$')]
        [Alias('Ids','detection_id','detection_ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('show_in_ui','comment','assigned_to_uuid','status','ids') }}
            Max = 1000
            Schema = 'Meta.Response'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($PSBoundParameters.Comment -and !$PSBoundParameters.Status) {
            throw "A 'status' value must be supplied when adding a comment."
        } elseif ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconDetection {
<#
.SYNOPSIS
Search for detections
.DESCRIPTION
Requires 'Detections: Read'.
.PARAMETER Id
Detection identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDetection
#>
    [CmdletBinding(DefaultParameterSetName='/detects/queries/detects/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Detection',
        ParameterSetName='/detects/entities/summaries/GET/v1:post')]
    [OutputType([string],ParameterSetName='/detects/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/summaries/GET/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^ldt:[a-fA-F0-9]{32}:\d+$')]
        [Alias('Ids','detection_id','detection_ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=3)]
        [ValidateSet('adversary_id.asc','adversary_id.desc','devices.hostname.asc','devices.hostname.desc',
            'first_behavior.asc','first_behavior.desc','last_behavior.asc','last_behavior.desc',
            'max_confidence.asc','max_confidence.desc','max_severity.asc','max_severity.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/detects/queries/detects/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('filter','q','sort','limit','offset')
            }
            Max = 1000
            Schema = switch ($PSCmdlet.ParameterSetName) {
                '/detects/entities/summaries/GET/v1:post' { 'Detection' }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonIoa
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/ioa/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Ioa',
        ParameterSetName='/detects/entities/ioa/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=1)]
        [ValidateSet('aws','azure',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id','account_id')]
        [string]$AwsAccountId,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_subscription_id','subscription_id')]
        [string]$AzureSubscriptionId,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_tenant_id','tenant_id')]
        [string]$AzureTenantId,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=5)]
        [ValidateSet('High','Medium','Informational',IgnoreCase=$false)]
        [string]$Severity,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=6)]
        [string]$Region,
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=7)]
        [ValidateSet('ACM','ACR','Any','App Engine','AppService','BigQuery','Cloud Load Balancing',
            'Cloud Logging','Cloud SQL','Cloud Storage','CloudFormation','CloudTrail','CloudWatch Logs',
            'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS','ELB','EMR',
            'Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis','Kubernetes','Lambda',
            'LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL','RDS','Redshift','S3','SES',
            'SNS','SQLDatabase','SQLServer','SQS','SSM','Serverless Application Repository','StorageAccount',
            'Subscriptions','VPC','VirtualMachine','VirtualNetwork',IgnoreCase=$false)]
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
        [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
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
            Schema = 'Horizon.Ioa'
        }
    }
    process {
        if (!$PSBoundParameters.CloudPlatform){
            $PSBoundParameters.CloudPlatform = if ($PSBoundParameters.AwsAccountId) {
                'aws'
            } elseif ($PSBoundParameters.AzureSubscriptionId -or $PSBoundParameters.AzureTenantId) {
                'azure'
            }
        }
        if (!$PSBoundParameters.CloudPlatform) {
            throw "'AwsAccountId', 'AzureSubscriptionId', 'AzureTenantId' or 'CloudPlatform' must be provided."
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
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
.PARAMETER Status
Indicator of Misconfiguration status
.PARAMETER Region
Cloud platform region
.PARAMETER Severity
Indicator of Misconfiguration severity
.PARAMETER Service
Cloud service
.PARAMETER Limit
Maximum number of results per request
.PARAMETER NextToken
Pagination token to retrieve the next set of results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonIom
#>
    [CmdletBinding(DefaultParameterSetName='/detects/entities/iom/v1:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Iom',ParameterSetName='/detects/entities/iom/v1:get')]
    param(
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=1)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^(\d{12}|\w{6,30})$')]
        [Alias('account_id','AwsAccountId')]
        [string]$AccountId,
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
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
            'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS','ELB','EMR',
            'Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis','Kubernetes','Lambda',
            'LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL','RDS','Redshift','S3','SES',
            'SNS','SQLDatabase','SQLServer','SQS','SSM','Serverless Application Repository','StorageAccount',
            'Subscriptions','VPC','VirtualMachine','VirtualNetwork',IgnoreCase=$false)]
        [string]$Service,
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get',Position=9)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/detects/entities/iom/v1:get')]
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
            Schema = 'Horizon.Iom'
        }
    }
    process {
        if (!$PSBoundParameters.CloudPlatform){
            $PSBoundParameters.CloudPlatform = if ($PSBoundParameters.AccountId) {
                if ($PSBoundParameters.AccountId -match '^\d{12}$') { 'aws' } else { 'gcp' }
            } elseif ($PSBoundParameters.AzureSubscriptionId -or $PSBoundParameters.AzureTenantId) {
                'azure'
            }
        }
        if (!$PSBoundParameters.CloudPlatform) {
            throw "'AwsAccountId', 'AzureSubscriptionId', 'AzureTenantId' or 'CloudPlatform' must be provided."
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
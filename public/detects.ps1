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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 1000 }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($PSBoundParameters.Comment -and !$PSBoundParameters.Status) {
      throw "A 'status' value must be supplied when adding a comment."
    } elseif ($List) {
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 1000 }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconHorizonIoa {
<#
.SYNOPSIS
Search for Falcon Horizon Indicators of Attack
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER AccountId
Cloud account identifier
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.PARAMETER ResourceId
Resource identifier
.PARAMETER ResourceUuid
Resource UUID
.PARAMETER Severity
Indicator of Attack severity
.PARAMETER Region
Cloud platform region
.PARAMETER Service
Cloud service
.PARAMETER State
Indicator of Attack state
.PARAMETER Since
Filter events using a duration string (e.g. 24h)
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
  param(
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Mandatory,Position=1)]
    [ValidateSet('aws','azure',IgnoreCase=$false)]
    [Alias('cloud_provider','cloud_platform')]
    [string]$CloudPlatform,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=2)]
    [Alias('account_id')]
    [string]$AccountId,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^\d{12}$')]
    [Alias('aws_account_id')]
    [string]$AwsAccountId,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('azure_subscription_id','subscription_id')]
    [string]$AzureSubscriptionId,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',ValueFromPipelineByPropertyName,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('azure_tenant_id','tenant_id')]
    [string]$AzureTenantId,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=6)]
    [Alias('resource_id')]
    [string[]]$ResourceId,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=7)]
    [Alias('resource_uuid')]
    [string[]]$ResourceUuid,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=8)]
    [ValidateSet('High','Medium','Informational',IgnoreCase=$false)]
    [string]$Severity,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=9)]
    [ValidateSet('ACM','ACR','Any','App Engine','AppService','BigQuery','Cloud Load Balancing',
      'Cloud Logging','Cloud SQL','Cloud Storage','CloudFormation','CloudTrail','CloudWatch Logs',
      'Cloudfront','Compute Engine','Config','Disk','DynamoDB','EBS','EC2','ECR','EFS','EKS','ELB','EMR',
      'Elasticache','GuardDuty','IAM','Identity','KMS','KeyVault','Kinesis','Kubernetes','Lambda',
      'LoadBalancer','Monitor','NLB/ALB','NetworkSecurityGroup','PostgreSQL','RDS','Redshift','S3','SES',
      'SNS','SQLDatabase','SQLServer','SQS','SSM','Serverless Application Repository','StorageAccount',
      'Subscriptions','VPC','VirtualMachine','VirtualNetwork',IgnoreCase=$false)]
    [string]$Service,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=10)]
    [ValidateSet('open','closed',IgnoreCase=$false)]
    [string]$State,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=11)]
    [string]$Since,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=12)]
    [Alias('date_time_since')]
    [string]$DateTimeSince,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get',Position=13)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
    [Alias('next_token')]
    [string]$NextToken,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/detects/entities/ioa/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconHorizonIom {
<#
.SYNOPSIS
Search for Falcon Horizon Indicators of Misconfiguration
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Id
Horizon Indicator of Misconfiguration identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER NextToken
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonIom
#>
  [CmdletBinding(DefaultParameterSetName='/detects/queries/iom/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/detects/entities/iom/v2:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get',Position=2)]
    [ValidateSet('account_name.asc','account_name.desc','account_id.asc','account_id.desc','attack_types.asc',
      'attack_types.desc','azure_subscription_id.asc','azure_subscription_id.desc','cloud_provider.asc',
      'cloud_provider.desc','cloud_service_keyword.asc','cloud_service_keyword.desc','status.asc',
      'status.desc','is_managed.asc','is_managed.desc','policy_id.asc','policy_id.desc','policy_type.asc',
      'policy_type.desc','resource_id.asc','resource_id.desc','region.asc','region.desc','scan_time.asc',
      'scan_time.desc','severity.asc','severity.desc','severity_string.asc','severity_string.desc',
      'timestamp.asc','timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get',Position=3)]
    [ValidateRange(1,1000)]
    [int]$Limit,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get')]
    [Alias('next_token')]
    [string]$NextToken,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/detects/queries/iom/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
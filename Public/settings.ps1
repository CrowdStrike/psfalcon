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
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconHorizonPolicy
#>
    [CmdletBinding(DefaultParameterSetName='/settings/entities/policy/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=1)]
        [ValidateSet('informational','medium','high',IgnoreCase=$false)]
        [string]$Severity,
        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=2)]
        [boolean]$Enabled,
        [Parameter(ParameterSetName='/settings/entities/policy/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
            Position=3)]
        [Alias('policy_id','PolicyId')]
        [int32]$Id
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
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconHorizonSchedule
#>
    [CmdletBinding(DefaultParameterSetName='/settings/scan-schedule/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/settings/scan-schedule/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            Position=1)]
        [ValidateSet('2h','6h','12h','24h',IgnoreCase=$false)]
        [Alias('scan_schedule')]
        [string]$ScanSchedule,
        [Parameter(ParameterSetName='/settings/scan-schedule/v1:post',Mandatory,ValueFromPipelineByPropertyName,
            Position=2)]
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonPolicy
#>
    [CmdletBinding(DefaultParameterSetName='/settings/entities/policy/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/settings/entities/policy-details/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Mandatory)]
        [ValidatePattern('^\d+$')]
        [Alias('Ids','policy_id')]
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
        [System.Collections.Generic.List[int32]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonSchedule
#>
    [CmdletBinding(DefaultParameterSetName='/settings/scan-schedule/v1:get',SupportsShouldProcess)]
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
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($CloudPlatform) { @($CloudPlatform).foreach{ $List.Add($_) }}
    }
    end {
        if ($List) {
            $PSBoundParameters['CloudPlatform'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
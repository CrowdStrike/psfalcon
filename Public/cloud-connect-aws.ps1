function Confirm-FalconDiscoverAwsAccess {
<#
.SYNOPSIS
Verify Falcon Discover for Cloud AWS account access
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/verify-account-access/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/verify-account-access/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
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
function Edit-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Modify a Falcon Discover for Cloud AWS account
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER ExternalId
AWS account identifier with cross-account IAM role access
.PARAMETER IamRoleArn
Full ARN of the IAM role created in the AWS account to control access
.PARAMETER CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.PARAMETER CloudtrailBucketRegion
AWS region where the account containing cloudtrail logs resides
.PARAMETER RateLimitTime
Number of seconds between requests defined by 'RateLimitReq'
.PARAMETER RateLimitReq
Maximum number of requests within 'RateLimitTime'
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('external_id')]
        [string]$ExternalId,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=2)]
        [Alias('iam_role_arn')]
        [string]$IamRoleArn,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('cloudtrail_bucket_owner_id')]
        [string]$CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=4)]
        [Alias('cloudtrail_bucket_region')]
        [string]$CloudtrailBucketRegion,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=5)]
        [Alias('rate_limit_time')]
        [int64]$RateLimitTime,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Position=6)]
        [Alias('rate_limit_reqs','RateLimitReqs')]
        [int32]$RateLimitReq,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=7)]
        [ValidatePattern('^\d{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ resources = @('rate_limit_time','external_id','rate_limit_reqs',
                    'cloudtrail_bucket_region','iam_role_arn','id','cloudtrail_bucket_owner_id') }
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Search for Falcon Discover for Cloud AWS accounts
.DESCRIPTION
Requires 'AWS Accounts: Read'.
.PARAMETER Id
AWS account identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/queries/accounts/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\d{12}$')]
        [Alias('ids')]
        [string[]]$Id,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get',Position=1)]
        [Parameter(ParameterSetName='/cloud-connect-aws/combined/accounts/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get',Position=2)]
        [Parameter(ParameterSetName='/cloud-connect-aws/combined/accounts/v1:get',Position=2)]
        [string]$Sort,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get',Position=3)]
        [Parameter(ParameterSetName='/cloud-connect-aws/combined/accounts/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int32]$Limit,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get',Position=4)]
        [Parameter(ParameterSetName='/cloud-connect-aws/combined/accounts/v1:get',Position=4)]
        [int32]$Offset,

        [Parameter(ParameterSetName='/cloud-connect-aws/combined/accounts/v1:get',Mandatory)]
        [switch]$Detailed,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get')]
        [switch]$All,

        [Parameter(ParameterSetName='/cloud-connect-aws/queries/accounts/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','limit','filter') }
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
function Get-FalconDiscoverAwsSetting {
<#
.SYNOPSIS
Retrieve Global Settings Falcon Discover for Cloud AWS accounts
.DESCRIPTION
Requires 'AWS Accounts: Read'.
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/combined/settings/v1:get')]
    param()
    process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}
function New-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Provision Falcon Discover for Cloud AWS Accounts
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER Id
AWS account identifier
.PARAMETER Mode
Provisioning mode [default: manual]
.PARAMETER ExternalId
AWS account identifier with cross-account IAM role access
.PARAMETER IamRoleArn
Full ARN of the IAM role created in the AWS account to control access
.PARAMETER CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.PARAMETER CloudtrailBucketRegion
AWS region where the account containing cloudtrail logs resides
.PARAMETER RateLimitTime
Number of seconds between requests defined by 'RateLimitReq'
.PARAMETER RateLimitReq
Maximum number of requests within 'RateLimitTime'
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/accounts/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName= $true,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [string]$Id,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=2)]
        [ValidateSet('cloudformation','manual',IgnoreCase=$false)]
        [string]$Mode,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('external_id')]
        [string]$ExternalId,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=4)]
        [Alias('iam_role_arn')]
        [string]$IamRoleArn,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=5)]
        [ValidatePattern('^\d{12}$')]
        [Alias('cloudtrail_bucket_owner_id')]
        [string]$CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=6)]
        [Alias('cloudtrail_bucket_region')]
        [string]$CloudtrailBucketRegion,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=7)]
        [Alias('rate_limit_time')]
        [int64]$RateLimitTime,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:post',Position=8)]
        [Alias('rate_limit_reqs','RateLimitReqs')]
        [int32]$RateLimitReq
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('mode')
                Body = @{ resources = @('rate_limit_time','external_id','rate_limit_reqs',
                    'cloudtrail_bucket_region','iam_role_arn','id','cloudtrail_bucket_owner_id') }
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Remove-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Remove Falcon Discover for Cloud AWS accounts
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/accounts/v1:delete')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:delete',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
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
function Update-FalconDiscoverAwsSetting {
<#
.SYNOPSIS
Create or update global settings applicable to all newly-provisioned Falcon Discover for Cloud AWS accounts
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.PARAMETER StaticExternalId
Default external identifier to apply to AWS accounts
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Discover-for-Cloud-and-Containers
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/settings/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/settings/v1:post',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('cloudtrail_bucket_owner_id')]
        [string]$CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName='/cloud-connect-aws/entities/settings/v1:post',
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('static_external_id')]
        [string]$StaticExternalId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ resources = @('cloudtrail_bucket_owner_id','static_external_id') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
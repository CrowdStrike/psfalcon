function Confirm-FalconDiscoverAwsAccess {
<#
.Synopsis
Performs an Access Verification check on the specified Falcon Discover for Cloud AWS Account IDs
.Parameter Ids
AWS account identifier(s)
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{12}$')]
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
function Edit-FalconDiscoverAwsAccount {
<#
.Synopsis
Update Falcon Discover for Cloud AWS Accounts by specifying the ID of the account and details to update
.Parameter Id
AWS account identifier
.Parameter ExternalId
AWS account identifier with cross-account IAM role access
.Parameter IamRoleArn
Full ARN of the IAM role created in the AWS account to control access
.Parameter CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.Parameter CloudtrailBucketRegion
AWS region where the account containing cloudtrail logs resides
.Parameter RateLimitTime
Number of seconds between requests defined by 'RateLimitReqs'
.Parameter RateLimitReqs
Maximum number of requests within 'RateLimitTime'
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 2)]
        [ValidatePattern('^\d{12}$')]
        [string] $ExternalId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 3)]
        [string] $IamRoleArn,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 4)]
        [ValidatePattern('^\d{12}$')]
        [string] $CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 5)]
        [string] $CloudtrailBucketRegion,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 6)]
        [int64] $RateLimitTime,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch', Position = 7)]
        [integer] $RateLimitReqs
    )
    begin {
        $Fields = @{
            CloudtrailBucketOwnerId = 'cloudtrail_bucket_owner_id'
            CloudtrailBucketRegion  = 'cloudtrail_bucket_region'
            ExternalId              = 'external_id'
            IamRoleArn              = 'iam_role_arn'
            RateLimitReqs           = 'rate_limit_reqs'
            RateLimitTime           = 'rate_limit_time'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('rate_limit_time', 'external_id', 'rate_limit_reqs', 'cloudtrail_bucket_region',
                        'iam_role_arn', 'id', 'cloudtrail_bucket_owner_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverAwsAccount {
<#
.Synopsis
Search for Falcon Discover for Cloud AWS accounts
.Parameter Ids
AWS account identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
cloud-connect-aws:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Position = 3)]
        [ValidateRange(1, 500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get')]
        [switch] $Total

        
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverAwsSettings {
<#
.Synopsis
Retrieve Global Settings for all provisioned AWS accounts in Falcon Discover for Cloud
.Role
cloud-connect-aws:read
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/combined/settings/v1:get')]
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
function New-FalconDiscoverAwsAccount {
<#
.Synopsis
Provision Falcon Discover for Cloud AWS Accounts by specifying details about the accounts to provision
.Parameter Id
AWS account identifier
.Parameter Mode
Provisioning mode [default: manual]
.Parameter ExternalId
AWS account identifier with cross-account IAM role access
.Parameter IamRoleArn
Full ARN of the IAM role created in the AWS account to control access
.Parameter CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.Parameter CloudtrailBucketRegion
AWS region where the account containing cloudtrail logs resides
.Parameter RateLimitTime
Number of seconds between requests defined by 'RateLimitReqs'
.Parameter RateLimitReqs
Maximum number of requests within 'RateLimitTime'
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 2)]
        [ValidateSet('cloudformation', 'manual')]
        [string] $Mode,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 3)]
        [ValidatePattern('^\d{12}$')]
        [string] $ExternalId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 4)]
        [string] $IamRoleArn,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 5)]
        [ValidatePattern('^\d{12}$')]
        [string] $CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 6)]
        [string] $CloudtrailBucketRegion,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 7)]
        [int64] $RateLimitTime,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post', Position = 8)]
        [integer] $RateLimitReqs
    )
    begin {
        $Fields = @{
            CloudtrailBucketOwnerId = 'cloudtrail_bucket_owner_id'
            CloudtrailBucketRegion  = 'cloudtrail_bucket_region'
            ExternalId              = 'external_id'
            IamRoleArn              = 'iam_role_arn'
            RateLimitReqs           = 'rate_limit_reqs'
            RateLimitTime           = 'rate_limit_time'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('mode')
                Body  = @{
                    resources = @('rate_limit_time', 'external_id', 'rate_limit_reqs', 'cloudtrail_bucket_region',
                        'iam_role_arn', 'id', 'cloudtrail_bucket_owner_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconDiscoverAwsAccount {
<#
.Synopsis
Delete Falcon Discover for Cloud AWS accounts
.Parameter Ids
AWS account identifier(s)
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
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
function Update-FalconDiscoverAwsSettings {
<#
.Synopsis
Create or update Global Settings which are applicable to all provisioned Falcon Discover for Cloud AWS accounts
.Parameter CloudtrailBucketOwnerId
AWS account identifier containing cloudtrail logs
.Parameter StaticExternalId
Default external identifier to apply to AWS accounts
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/settings/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/settings/v1:post', Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/settings/v1:post', Position = 2)]
        [ValidatePattern('^\d{12}$')]
        [string] $StaticExternalId
    )
    begin {
        $Fields = @{
            CloudtrailBucketOwnerId = 'cloudtrail_bucket_owner_id'
            StaticExternalId        = 'static_external_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('cloudtrail_bucket_owner_id', 'static_external_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
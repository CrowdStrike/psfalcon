function Confirm-FalconDiscoverAwsAccess {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{12}$')]
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
function Edit-FalconDiscoverAwsAccount {
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
        [int] $RateLimitReqs
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-aws/queries/accounts/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/cloud-connect-aws/combined/accounts/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
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
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverAwsSetting {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/combined/settings/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function New-FalconDiscoverAwsAccount {
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
        [int] $RateLimitReqs
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Remove-FalconDiscoverAwsAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
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
function Update-FalconDiscoverAwsSetting {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
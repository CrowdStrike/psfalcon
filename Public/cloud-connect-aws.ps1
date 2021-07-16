function Get-FalconDiscoverAwsSettings {
<#
.Synopsis
Retrieve Global Settings for all provisioned AWS accounts
.Role
cloud-connect-aws:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
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
function New-FalconAccounts {
<#
.Synopsis
Provision AWS Accounts by specifying details about the accounts to provision
.Parameter RateLimitTime

.Parameter ExternalId

.Parameter RateLimitReqs

.Parameter CloudtrailBucketRegion

.Parameter IamRoleArn

.Parameter Mode

.Parameter Id
XXX identifier
.Parameter CloudtrailBucketOwnerId

.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [int64] $RateLimitTime,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [string] $ExternalId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [integer] $RateLimitReqs,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [string] $CloudtrailBucketRegion,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [string] $IamRoleArn,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [ValidateSet('cloudformation', 'manual')]
        [string] $Mode,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [string] $Id,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:post')]
        [string] $CloudtrailBucketOwnerId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
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
function New-FalconVerifyAccountAccess {
<#
.Synopsis
Performs an Access Verification check on the specified AWS Account IDs
.Parameter Ids
One or more XXX identifiers
.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/verify-account-access/v1:post',
            Mandatory = $true)]
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
function Remove-FalconDiscoverAwsAccount {
<#
.Synopsis
Delete AWS accounts from Falcon Discover
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
function Get-FalconDiscoverAWSAccount {
<#
.Synopsis
Search for AWS accounts in Falcon Discover
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
function Edit-FalconAccounts {
<#
.Synopsis
Update AWS Accounts by specifying the ID of the account and details to update
.Parameter RateLimitTime

.Parameter ExternalId

.Parameter RateLimitReqs

.Parameter CloudtrailBucketRegion

.Parameter IamRoleArn

.Parameter Id
XXX identifier
.Parameter CloudtrailBucketOwnerId

.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [int64] $RateLimitTime,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [string] $ExternalId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [integer] $RateLimitReqs,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [string] $CloudtrailBucketRegion,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [string] $IamRoleArn,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [string] $Id,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/accounts/v1:patch')]
        [string] $CloudtrailBucketOwnerId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
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
function New-FalconSettings {
<#
.Synopsis
Create or update Global Settings which are applicable to all provisioned AWS accounts
.Parameter CloudtrailBucketOwnerId

.Parameter StaticExternalId

.Role
cloud-connect-aws:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-aws/entities/settings/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/settings/v1:post')]
        [string] $CloudtrailBucketOwnerId,

        [Parameter(ParameterSetName = '/cloud-connect-aws/entities/settings/v1:post')]
        [string] $StaticExternalId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
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
function Confirm-FalconDiscoverAwsAccess {
<#
.SYNOPSIS
Verify Falcon Discover for Cloud AWS account access
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Confirm-FalconDiscoverAwsAccess
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/verify-account-access/v1:post',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Account.Access',
        ParameterSetName='/cloud-connect-aws/entities/verify-account-access/v1:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/verify-account-access/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
            Schema = 'Horizon.Aws.Account.Access'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
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
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDiscoverAwsAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Account',
        ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\d{12}$')]
        [Alias('external_id')]
        [string]$ExternalId,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('iam_role_arn')]
        [string]$IamRoleArn,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('cloudtrail_bucket_owner_id')]
        [string]$CloudtrailBucketOwnerId,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=4)]
        [Alias('cloudtrail_bucket_region')]
        [string]$CloudtrailBucketRegion,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=5)]
        [Alias('rate_limit_time')]
        [int64]$RateLimitTime,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',
            ValueFromPipelineByPropertyName,Position=6)]
        [Alias('rate_limit_reqs','RateLimitReqs')]
        [int32]$RateLimitReq,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/accounts/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,Position=7)]
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
            Schema = 'Horizon.Aws.Account'
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
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
AWS account status
.PARAMETER Migrated
Account migration status
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAwsAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/account/v2:get',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Account',
        ParameterSetName='/cloud-connect-aws/entities/account/v2:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [ValidatePattern('^\d{12}$')]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',Position=1)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [Alias('organization-ids')]
        [string[]]$OrganizationId,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',Position=2)]
        [ValidateSet('full','dry',IgnoreCase=$false)]
        [Alias('scan-type')]
        [string]$ScanType,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',Position=3)]
        [ValidateSet('provisioned','operational',IgnoreCase=$false)]
        [string]$Status,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',Position=4)]
        [boolean]$Migrated,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get',Position=5)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('migrated','ids','scan-type','status','limit','organization-ids','offset') }
            Schema = 'Horizon.Aws.Account'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconDiscoverAwsLink {
<#
.SYNOPSIS
Retrieve previously generated Falcon Discover AWS CloudFormation links
.DESCRIPTION
Requires 'AWS Accounts: Read'.
.PARAMETER Region
AWS region
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAwsLink
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/console-setup-urls/v1:get',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Link',
        ParameterSetName='/cloud-connect-aws/entities/console-setup-urls/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/console-setup-urls/v1:get',Position=1)]
        [string]$Region
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('region') }
            Schema = 'Horizon.Aws.Link'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconDiscoverAwsSetting {
<#
.SYNOPSIS
Retrieve global settings for Cloud AWS accounts in Falcon Discover
.DESCRIPTION
Requires 'AWS Accounts: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAwsSetting
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/combined/settings/v1:get',SupportsShouldProcess)]
    param()
    process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}
function New-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Provision Falcon Discover for Cloud AWS Accounts
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER AccountType
AWS account type
.PARAMETER IsMaster
AWS master account status
.PARAMETER CloudtrailRegion
AWS region where the account containing cloudtrail logs resides
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDiscoverAwsAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/account/v2:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Account',
        ParameterSetName='/cloud-connect-aws/entities/account/v2:post')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:post',ValueFromPipelineByPropertyName,
            Position=1)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [Alias('organization_id')]
        [string]$OrganizationId,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:post',ValueFromPipelineByPropertyName,
            Position=2)]
        [ValidateSet('commercial','gov',IgnoreCase=$false)]
        [Alias('account_type')]
        [string]$AccountType,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [Alias('is_master')]
        [boolean]$IsMaster,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [Alias('cloudtrail_region')]
        [string]$CloudtrailRegion,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^\d{12}$')]
        [Alias('account_id')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    resources = @('account_id','account_type','cloudtrail_region','is_master','organization_id')
                }
            }
            Schema = 'Horizon.Aws.Account'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Receive-FalconDiscoverAwsScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Discover access using the AWS CLI
.DESCRIPTION
Requires 'AWS Accounts: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
AWS Account identifier
.PARAMETER Force
Overwrite existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconDiscoverAwsScript
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/user-scripts-download/v1:get',
        SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Script',
        ParameterSetName='/cloud-connect-aws/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/user-scripts-download/v1:get',Mandatory,
            Position=1)]
        [string]$Path,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/user-scripts-download/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [Alias('ids','account_id')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/user-scripts-download/v1:get')]
        [switch]$Force
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{ Accept = 'application/octet-stream' }
            Format = @{
                Query = @('ids')
                Outfile = 'path'
            }
            Schema = 'Horizon.Aws.Script'
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
function Remove-FalconDiscoverAwsAccount {
<#
.SYNOPSIS
Remove Falcon Discover for Cloud AWS accounts
.DESCRIPTION
Requires 'AWS Accounts: Write'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER Id
AWS account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDiscoverAwsAccount
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/account/v2:delete',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.msa.BaseEntitiesResponse',
        ParameterSetName='/cloud-connect-aws/entities/account/v2:delete')]
    param(
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^o-[0-9a-z]{10,32}$')]
        [Alias('organization-ids')]
        [string[]]$OrganizationId,
        [Parameter(ParameterSetName='/cloud-connect-aws/entities/account/v2:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
        [ValidatePattern('^\d{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','organization-ids') }
            Schema = 'msa.BaseEntitiesResponse'
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_)}}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
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
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconDiscoverAwsSetting
#>
    [CmdletBinding(DefaultParameterSetName='/cloud-connect-aws/entities/settings/v1:post',SupportsShouldProcess)]
    [OutputType('CrowdStrike.Falcon.Horizon.Aws.Account.Setting',
        ParameterSetName='/cloud-connect-aws/entities/settings/v1:post')]
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
            Schema = 'Horizon.Aws.Account.Setting'
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
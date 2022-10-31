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
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.PARAMETER UserIds
User identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonIoaEvent
#>
    [CmdletBinding(DefaultParameterSetName='/ioa/entities/events/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidatePattern('^\d+$')]
        [Alias('policy_id')]
        [int32]$PolicyId,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=2)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id','account_id','AccountId')]
        [string]$AwsAccountId,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_tenant_id')]
        [string]$AzureTenantId,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=6)]
        [Alias('user_ids')]
        [string[]]$UserIds,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get',Position=7)]
        [ValidateRange(1,500)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ioa/entities/events/v1:get')]
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
function Get-FalconHorizonIoaUser {
<#
.SYNOPSIS
Search for Falcon Horizon Indicator of Attack users
.DESCRIPTION
Requires 'CSPM Registration: Read'.
.PARAMETER PolicyId
Policy identifier
.PARAMETER CloudPlatform
Cloud platform
.PARAMETER AwsAccountId
AWS account identifier
.PARAMETER AzureSubscriptionId
Azure subscription identifier
.PARAMETER AzureTenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHorizonIoaUser
#>
    [CmdletBinding(DefaultParameterSetName='/ioa/entities/users/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',Mandatory,ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidatePattern('^\d+$')]
        [Alias('policy_id')]
        [int32]$PolicyId,
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',Position=2)]
        [ValidateSet('aws','azure','gcp',IgnoreCase=$false)]
        [Alias('cloud_provider','cloud_platform')]
        [string]$CloudPlatform,
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\d{12}$')]
        [Alias('aws_account_id','account_id','AccountId')]
        [string]$AwsAccountId,
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
        [Alias('azure_subscription_id')]
        [string]$AzureSubscriptionId,
        [Parameter(ParameterSetName='/ioa/entities/users/v1:get',ValueFromPipelineByPropertyName,Position=5)]
        [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
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
function Get-FalconDiscoverAwsScript {
<#
.SYNOPSIS
Generate a bulk registration script for Falcon Discover
.DESCRIPTION
Requires 'AWS accounts: Read'.
.PARAMETER OrganizationId
AWS organization identifier
.PARAMETER AccountType
Account type, when registering AWS commercial account in a Gov environment
.PARAMETER SingleAccount
Provide static script for a single AWS account
.PARAMETER Delete
Generate a delete script
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAwsScript
#>
  [CmdletBinding(DefaultParameterSetName='/settings-discover/entities/gen/scripts/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/settings-discover/entities/gen/scripts/v1:get',Position=1,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^o-[0-9a-z]{10,32}$')]
    [Alias('organization-id','organization_id')]
    [string]$OrganizationId,
    [Parameter(ParameterSetName='/settings-discover/entities/gen/scripts/v1:get',Position=2,
      ValueFromPipelineByPropertyName)]
    [ValidateSet('commercial','gov',IgnoreCase=$false)]
    [Alias('account_type')]
    [string]$AccountType,
    [Parameter(ParameterSetName='/settings-discover/entities/gen/scripts/v1:get',Position=3)]
    [Alias('single_account')]
    [boolean]$SingleAccount,
    [Parameter(ParameterSetName='/settings-discover/entities/gen/scripts/v1:get',Position=4)]
    [boolean]$Delete
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
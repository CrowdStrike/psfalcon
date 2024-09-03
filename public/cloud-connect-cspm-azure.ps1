function Edit-FalconCloudAzureAccount {
<#
.SYNOPSIS
Modify the default Falcon Cloud Security Azure client or subscription identifier
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER Id
Azure client identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier, required when multiple tenants have been registered
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCloudAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',
    SupportsShouldProcess)]
  [Alias('Edit-FalconHorizonAzureAccount')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string]$SubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/client-id/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/default-subscription-id/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant-id','tenant_id')]
    [string]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCloudAzureAccount {
<#
.SYNOPSIS
Search for Falcon Cloud Security Azure accounts
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Id
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER ScanType
Scan type
.PARAMETER Status
Azure account status
.PARAMETER CspmLite
Only return CSPM Lite accounts
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',
    SupportsShouldProcess)]
  [Alias('Get-FalconHorizonAzureAccount')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_ids')]
    [string[]]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=3)]
    [ValidateSet('full','dry',IgnoreCase=$false)]
    [Alias('scan-type')]
    [string]$ScanType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=4)]
    [ValidateSet('provisioned','operational',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=5)]
    [Alias('cspm_lite')]
    [boolean]$CspmLite,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get',Position=6)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconCloudAzureCertificate {
<#
.SYNOPSIS
Retrieve the base64 encoded certificate for a Falcon Cloud Security Azure tenant
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER Refresh
Refresh certificate [default: false]
.PARAMETER YearsValid
Years the certificate should be valid [when Refresh: true]
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudAzureCertificate
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',
    SupportsShouldProcess)]
  [Alias('Get-FalconHorizonAzureCertificate')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',Position=1)]
    [boolean]$Refresh,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',Position=2)]
    [ValidatePattern('^[0-9]{1,2}$')]
    [Alias('years_valid')]
    [string]$YearsValid,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/download-certificate/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string[]]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCloudAzureGroup {
<#
.SYNOPSIS
Retrieve Falcon Cloud Security Azure management group registration
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudAzureGroup
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:get',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_ids')]
    [string[]]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:get',Position=2)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:get')]
    [int32]$Offset
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconCloudAzureAccount {
<#
.SYNOPSIS
Provision a Falcon Cloud Security Azure account
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER ClientId
Azure client identifier
.PARAMETER AccountType
Azure account type
.PARAMETER DefaultSubscription
Account is the default Azure subscription
.PARAMETER YearsValid
Number of years valid
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCloudAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
    SupportsShouldProcess)]
  [Alias('New-FalconHorizonAzureAccount')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string]$SubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',Position=3)]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',Position=4)]
    [Alias('account_type')]
    [string]$AccountType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',Position=5)]
    [Alias('default_subscription')]
    [boolean]$DefaultSubscription,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:post',Position=6)]
    [Alias('years_valid')]
    [int]$YearsValid
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconCloudAzureGroup {
<#
.SYNOPSIS
Create a Falcon Cloud Security Azure management group
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER DefaultSubscriptionId
Default Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCloudAzureGroup
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:post',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('default_subscription_id')]
    [string]$DefaultSubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconCloudAzureScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Cloud Security access using Azure Cloud Shell
.DESCRIPTION
Requires 'CSPM registration: Read'.
.PARAMETER TenantId
Azure tenant identifier [default: most recently registered]
.PARAMETER SubscriptionId
Azure subscription identifier [default: all]
.PARAMETER Template
Template to be rendered
.PARAMETER AccountType
Account type
.PARAMETER AzureManagementGroup
Use Azure Management Group
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconCloudAzureScript
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
    SupportsShouldProcess)]
  [Alias('Receive-FalconHorizonAzureScript')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant-id','tenant_id')]
    [string]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('subscription_ids')]
    [string[]]$SubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Position=3)]
    [string]$Template,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Position=4)]
    [ValidateSet('commercial','gov',IgnoreCase=$false)]
    [Alias('account_type')]
    [string]$AccountType,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Position=5)]
    [Alias('azure_management_group')]
    [boolean]$AzureManagementGroup,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get',Mandatory,
      Position=5)]
    [string]$Path,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
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
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconCloudAzureAccount {
<#
.SYNOPSIS
Remove Falcon Cloud Security Azure accounts
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER RetainTenant
Retain Azure tenant when removing an account
.PARAMETER Id
Azure account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCloudAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',
    SupportsShouldProcess)]
  [Alias('Remove-FalconHorizonAzureAccount')]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_ids')]
    [string[]]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',Position=2)]
    [Alias('retain_tenant')]
    [boolean]$RetainTenant,
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/account/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconCloudAzureGroup {
<#
.SYNOPSIS
Remove Falcon Cloud Security Azure management groups
.DESCRIPTION
Requires 'CSPM registration: Write'.
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCloudAzureGroup
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-cspm-azure/entities/management-group/v1:delete',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('tenant_ids')]
    [string[]]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
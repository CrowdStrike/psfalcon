function Get-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Search for Falcon Discover for Cloud Azure accounts
.DESCRIPTION
Requires 'D4C registration: Read'.
.PARAMETER ScanType
Scan type
.PARAMETER TenantId
Tenant ids to filter azure accounts
.PARAMETER Status
Account status to filter results by
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.PARAMETER Id
Azure account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=1)]
    [ValidateSet('full','dry',IgnoreCase=$false)]
    [Alias('scan-type')]
    [string]$ScanType,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('tenant_ids')]
    [string[]]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=3)]
    [ValidateSet('provisioned','operational',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',Position=4)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get')]
    [switch]$Total,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('Ids')]
    [string[]]$Id
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
function Get-FalconDiscoverAzureCertificate {
<#
.SYNOPSIS
Retrieve the base64 encoded certificate for a Falcon Discover Azure tenant
.DESCRIPTION
Requires 'D4C registration: Read'.
.PARAMETER Refresh
Refresh certificate [default: false]
.PARAMETER YearsValid
Years the certificate should be valid (when Refresh is true)
.PARAMETER TenantId
Azure tenant identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAzureCertificate
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',Position=1)]
    [boolean]$Refresh,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',Position=2)]
    [Alias('years_valid')]
    [int]$YearsValid,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/download-certificate/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string[]]$TenantId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconDiscoverAzureTenant {
<#
.SYNOPSIS
List Falcon Discover for Cloud Azure tenants
.DESCRIPTION
Requires 'D4C registration: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDiscoverAzureTenant
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/tenant-id/v1:get',SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function New-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Provision Falcon Discover for Cloud Azure accounts
.DESCRIPTION
Requires 'D4C registration: Write'.
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER ClientId
Azure client identifier
.PARAMETER AccountType
Account type
.PARAMETER YearsValid
Years the certificate should be valid
.PARAMETER DefaultSubscription
Default subscription
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDiscoverAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/account/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('subscription_id')]
    [string]$SubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('tenant_id')]
    [string]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('client_id')]
    [string]$ClientId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('account_type')]
    [string]$AccountType,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=5)]
    [Alias('years_valid')]
    [int]$YearsValid,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/account/v1:post',
      ValueFromPipelineByPropertyName,Position=6)]
    [Alias('default_subscription')]
    [boolean]$DefaultSubscription
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconDiscoverAzureScript {
<#
.SYNOPSIS
Download a Bash script which grants Falcon Discover for Cloud access using Azure Cloud Shell
.DESCRIPTION
Requires 'D4C registration: Read'.
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER SubscriptionId
Azure subscription identifier
.PARAMETER Template
Template to be rendered
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconDiscoverAzureScript
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('tenant-id')]
    [string[]]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('subscription_ids')]
    [string[]]$SubscriptionId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',Position=3)]
    [string]$Template,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get',Mandatory,Position=4)]
    [string]$Path,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/user-scripts-download/v1:get')]
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
function Update-FalconDiscoverAzureAccount {
<#
.SYNOPSIS
Update the Azure Service Principal for Falcon Discover for Cloud
.DESCRIPTION
Requires 'D4C registration: Write'.
.PARAMETER TenantId
Azure tenant identifier
.PARAMETER ObjectId
Azure object identifier
.PARAMETER Id
Azure client identifier for the associated Service Principal
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconDiscoverAzureAccount
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('tenant-id')]
    [string]$TenantId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [Alias('object_id')]
    [string]$ObjectId,
    [Parameter(ParameterSetName='/cloud-connect-azure/entities/client-id/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
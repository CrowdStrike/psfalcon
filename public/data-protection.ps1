function Confirm-NullNotification ([object]$Object) {
  @('custom_allow_notification','custom_block_notification').foreach{
    # Force 'custom_allow_notification' and 'custom_block_notification' to $null when empty [string]
    if ([string]::IsNullOrEmpty($Object.$_) -and $null -ne $Object.$_) { $Object.$_ = $null }
  }
}
function Edit-FalconDataProtectionAccount {
<#
.SYNOPSIS
Modify a Falcon Data Protection enterprise account
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Name
Enterprise account name
.PARAMETER Domain
Domain names
.PARAMETER ApplicationGroupId
Application group identifier
.PARAMETER PluginConfigId
Plugin configuration identifier
.PARAMETER Id
Enterprise account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionAccount
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('domains')]
    [string[]]$Domain,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('application_group_id')]
    [string]$ApplicationGroupId,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('plugin_config_id')]
    [string]$PluginConfigId,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('application_group_id','domains','name','plugin_config_id') }
        Query = @('id')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconDataProtectionApplication {
<#
.SYNOPSIS
Modify a Falcon Data Protection cloud application
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Name
Cloud application name
.PARAMETER Url
Objects containing URL properties ('fqdn', 'path')
.PARAMETER Description
Cloud application description
.PARAMETER Id
Cloud application identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionApplication
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/cloud-applications/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('urls')]
    [object[]]$Url,
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('description','name','urls') }
        Query = @('id')
      }
    }
  }
  process {
    if ($PSBoundParameters.Url) {
      # Filter 'urls'
      $PSBoundParameters.Url = [PSCustomObject[]]@($PSBoundParameters.Url | Select-Object fqdn,path)
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconDataProtectionClassification {
<#
.SYNOPSIS
Modify a Falcon Data Protection classification
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Name
Classification name
.PARAMETER ClassificationProperties
Object containing classification properties ('content_patterns', 'evidence_duplication_enabled', 'file_types',
'protection_mode', 'rules', 'scan_profiles', 'sensitivity_labels', 'web_sources')
.PARAMETER Id
Classification identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionClassification
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/classifications/v2:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('classification_properties')]
    [object]$ClassificationProperties,
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ resources = @('classification_properties','id','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconDataProtectionLocation {
<#
.SYNOPSIS
Modify a Falcon Data Protection web location
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER ApplicationId
Application identifier
.PARAMETER Name
Web location name
.PARAMETER LocationType
Web location type
.PARAMETER EnterpriseAccountId
Enterprise account identifier
.PARAMETER ProviderLocationId
Provider location identifier
.PARAMETER ProviderLocationName
Provider location name
.PARAMETER Id
Web location identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionLocation
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/web-locations/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('application_id')]
    [string]$ApplicationId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('location_type')]
    [string]$LocationType,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('enterprise_account_id')]
    [string]$EnterpriseAccountId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('provider_location_id')]
    [string]$ProviderLocationId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',
      ValueFromPipelineByPropertyName,Position=6)]
    [Alias('provider_location_name')]
    [string]$ProviderLocationName,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('application_id','enterprise_account_id','location_type','name','provider_location_id',
            'provider_location_name','type')
        }
        Query = @('id')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Modify a Falcon Data Protection policy
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER InputObject
One or more policies to modify in a request
.PARAMETER PlatformName
Operating system
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER HostGroup
Assigned host groups
.PARAMETER IsEnabled
Policy status
.PARAMETER Precedence
Policy precedence
.PARAMETER PolicyProperties
An object containing policy properties
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/policies/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'Edit-FalconDataProtectionPolicy' '/data-protection/entities/policies/v2:patch'
    })]
    [Alias('resources')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Mandatory,Position=1)]
    [ValidateSet('win','mac',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=3)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=4)]
    [string]$Description,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=5)]
    [Alias('host_groups')]
    [object]$HostGroup,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=6)]
    [Alias('is_enabled')]
    [boolean]$IsEnabled,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=7)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Position=8)]
    [Alias('policy_properties')]
    [object]$PolicyProperties
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/data-protection/entities/policies/v2:patch'
      Format = @{
        Body = @{
          resources = @('description','host_groups','id','is_enabled','name','policy_properties','precedence')
        }
        Query = @('platform_name')
      }
    }
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $List.Add(([PSCustomObject]$_ | Select-Object @($Param.Format.Body.resources + 'platform_name')))
      }
    } else {
      if ($PSBoundParameters.PolicyProperties) { Confirm-NullNotification $PSBoundParameters.PolicyProperties }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 10 by 'platform_name'
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format.Body = @{ root = @('resources') }
      foreach ($Name in @($List.platform_name | Group-Object).Name) {
        [System.Collections.Generic.List[PSCustomObject]]$PnList = @($List).Where({$_.platform_name -eq $Name})
        foreach ($p in $PnList) { if ($p.policy_properties) { Confirm-NullNotification $p.policy_properties }}
        for ($i=0;$i -lt $PnList.Count;$i+=9) {
          $PSBoundParameters['platform_name'] = $Name
          $PSBoundParameters['resources'] = @($PnList[$i..($i+9)])
          Invoke-Falcon @Param -UserInput $PSBoundParameters
        }
      }
    }
  }
}
function Get-FalconDataProtectionAccount {
<#
.SYNOPSIS
Search for Falcon Data Protection enterprise accounts
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Enterprise account identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionAccount
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/enterprise-accounts/v2:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get',Position=2)]
    [ValidateSet('application_group_id|asc','application_group_id|desc','created_at|asc','created_at|desc',
      'deleted|asc','deleted|desc','name|asc','name|desc','updated_at|asc','updated_at|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/enterprise-accounts/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionApplication {
<#
.SYNOPSIS
Search for Falcon Data Protection cloud applications
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Cloud application identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionApplication
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/cloud-applications/v2:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get',Position=2)]
    [ValidateSet('application_group_id|asc','application_group_id|desc','deleted|asc','deleted|desc','name|asc',
      'name|desc','type|asc','type|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/cloud-applications/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionClassification {
<#
.SYNOPSIS
Search for Falcon Data Protection classifications
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Classification identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionClassification
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/classifications/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get',Position=2)]
    [ValidateSet('created_at|asc','created_at|desc','modified_at|asc','modified_at|desc','name|asc','name|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/classifications/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionLabel {
<#
.SYNOPSIS
Search for Falcon Data Protection sensitivity labels
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Sensitivity label identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionLabel
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/labels/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/labels/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get',Position=2)]
    [ValidateSet('created_at|asc','created_at|desc','deleted|asc','deleted|desc','display_name|asc',
      'display_name|desc','name|asc','name|desc','updated_at|asc','updated_at|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/labels/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionLocation {
<#
.SYNOPSIS
Search for Falcon Data Protection web locations
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Web location identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Type
The type of entity to query
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionLocation
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/web-locations/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get',Position=1)]
    [ValidateSet('custom','predefined',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/web-locations/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionPattern {
<#
.SYNOPSIS
Search for Falcon Data Protection content patterns
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Content pattern identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionPattern
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/content-patterns/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/content-patterns/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get',Position=2)]
    [ValidateSet('category|asc','category|desc','created_at|asc','created_at|desc','deleted|asc','deleted|desc',
      'example|asc','example|desc','name|asc','name|desc','region|asc','region|desc','type|asc','type|desc',
      'updated_at|asc','updated_at|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/content-patterns/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Search for Falcon Data Protection policies
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
Policy identifier
.PARAMETER PlatformName
Operating system platform
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionClassification
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/policies/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get',Mandatory,Position=1)]
    [ValidateSet('mac','win',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get',Position=3)]
    [ValidateSet('created_at|asc','created_at|desc','modified_at|asc','modified_at|desc','name|asc','name|desc',
      'precedence|asc','precedence|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get',Position=4)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/policies/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','platform_name','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDataProtectionType {
<#
.SYNOPSIS
Search for Falcon Data Protection file types
.DESCRIPTION
Requires 'Data Protection: Read'.
.PARAMETER Id
File type identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDataProtectionType
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/queries/file-types/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/file-types/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get',Position=2)]
    [ValidateSet('created_at|asc','created_at|desc','name|asc','name|desc','updated_at|asc','updated_at|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/data-protection/queries/file-types/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconDataProtectionAccount {
<#
.SYNOPSIS
Create a Falcon Data Protection enterprise account
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Name
Enterprise account name
.PARAMETER Domain
Domain names
.PARAMETER ApplicationGroupId
Application group identifier
.PARAMETER PluginConfigId
Plugin configuration identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDataProtectionAccount
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/enterprise-accounts/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('domains')]
    [string[]]$Domain,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('application_group_id')]
    [string]$ApplicationGroupId,
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:post',
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('plugin_config_id')]
    [string]$PluginConfigId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('application_group_id','domains','name','plugin_config_id') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconDataProtectionApplication {
<#
.SYNOPSIS
Create a Falcon Data Protection cloud application
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Name
Cloud application name
.PARAMETER Url
Objects containing URL properties ('fqdn', 'path')
.PARAMETER Description
Cloud application description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDataProtectionApplication
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/cloud-applications/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('urls')]
    [object[]]$Url,
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [string]$Description
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('description','name','urls') }}
    }
  }
  process {
    if ($PSBoundParameters.Url) {
      # Filter 'urls'
      $PSBoundParameters.Url = [PSCustomObject[]]@($PSBoundParameters.Url | Select-Object fqdn,path)
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function New-FalconDataProtectionClassification {
<#
.SYNOPSIS
Create a Falcon Data Protection classification
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER InputObject
One or more classifications to create
.PARAMETER Name
Classification name
.PARAMETER ClassificationProperties
Object containing classification properties ('content_patterns', 'evidence_duplication_enabled', 'file_types',
'protection_mode', 'rules', 'scan_profiles', 'sensitivity_labels', 'web_sources')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDataProtectionClassification
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/classifications/v2:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({ Confirm-Parameter $_ 'New-FalconDataProtectionClassification' (
      '/data-protection/entities/classifications/v2:post') })]
    [Alias('resources')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:post',Position=2)]
    [Alias('classification_properties')]
    [object]$ClassificationProperties
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/data-protection/entities/classifications/v2:post'
      Format = @{ Body = @{ resources = @('classification_properties','name') }}
    }
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      # Filter to defined 'resources' properties
      @($InputObject).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.resources)) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 10
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format.Body = @{ root = @('resources') }
      for ($i=0;$i -lt $List.Count;$i+=10) {
        $PSBoundParameters['resources'] = @($List[$i..($i+9)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function New-FalconDataProtectionLocation {
<#
.SYNOPSIS
Create a Falcon Data Protection web location
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER InputObject
One or more web locations to create
.PARAMETER Name
Web location name
.PARAMETER ApplicationId
Application identifier
.PARAMETER EnterpriseAccountId
Enterprise account identifier
.PARAMETER ProviderLocationId
Provider location identifier
.PARAMETER ProviderLocationName
Provider location name
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDataProtectionLocation
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/web-locations/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'New-FalconDataProtectionLocation' '/data-protection/entities/web-locations/v2:post'
    })]
    [Alias('web_locations')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('application_id')]
    [string]$ApplicationId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:post',Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('enterprise_account_id')]
    [string]$EnterpriseAccountId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:post',Position=4)]
    [Alias('provider_location_id')]
    [string]$ProviderLocationId,
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:post',Position=5)]
    [Alias('provider_location_name')]
    [string]$ProviderLocationName
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/data-protection/entities/web-locations/v2:post'
      Format = @{
        Body = @{
          web_locations = @('application_id','enterprise_account_id','name','provider_location_id',
          'provider_location_name')
        }
      }
    }
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      # Filter to defined 'web_locations' properties
      @($InputObject).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.web_locations)) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 10
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format.Body = @{ root = @('web_locations') }
      for ($i=0;$i -lt $List.Count;$i+=10) {
        $PSBoundParameters['web_locations'] = @($List[$i..($i+9)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function New-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Create a Falcon Data Protection policy
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER InputObject
One or more policies to create in a request
.PARAMETER PlatformName
Operating system
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Precedence
Policy precedence
.PARAMETER PolicyProperties
Object containing policy properties ('enable_content_inspection', 'enable_context_inspection', etc.)
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDataProtectionPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/policies/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'New-FalconDataProtectionPolicy' '/data-protection/entities/policies/v2:post'
    })]
    [Alias('resources')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Mandatory,Position=1)]
    [ValidateSet('win','mac',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Mandatory,Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Mandatory,Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Position=4)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Position=5)]
    [Alias('policy_properties')]
    [object]$PolicyProperties
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/data-protection/entities/policies/v2:post'
      Format = @{
        Body = @{ resources = @('description','name','policy_properties','precedence') }
        Query = @('platform_name')
      }
    }
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $List.Add(([PSCustomObject]$_ | Select-Object @($Param.Format.Body.resources + 'platform_name')))
      }
    } else {
      if ($PSBoundParameters.PolicyProperties) { Confirm-NullNotification $PSBoundParameters.PolicyProperties }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 10 by 'platform_name'
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format.Body = @{ root = @('resources') }
      foreach ($Name in @($List.platform_name | Group-Object).Name) {
        [System.Collections.Generic.List[PSCustomObject]]$PnList = @($List).Where({$_.platform_name -eq $Name})
        foreach ($p in $PnList) { if ($p.policy_properties) { Confirm-NullNotification $p.policy_properties }}
        for ($i=0;$i -lt $PnList.Count;$i+=9) {
          $PSBoundParameters['platform_name'] = $Name
          $PSBoundParameters['resources'] = @($PnList[$i..($i+9)])
          Invoke-Falcon @Param -UserInput $PSBoundParameters
        }
      }
    }
  }
}
function Remove-FalconDataProtectionAccount {
<#
.SYNOPSIS
Remove Falcon Data Protection enterprise accounts
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Enterprise account identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionAccount
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/enterprise-accounts/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/enterprise-accounts/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionApplication {
<#
.SYNOPSIS
Remove Falcon Data Protection cloud applications
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Cloud application identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionApplication
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/cloud-applications/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/cloud-applications/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionClassification {
<#
.SYNOPSIS
Remove Falcon Data Protection classifications
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Classification identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionClassification
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/classifications/v2:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionLabel {
<#
.SYNOPSIS
Remove Falcon Data Protection sensitivity labels
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Sensitivity label identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionLabel
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/labels/v2:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/labels/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionLocation {
<#
.SYNOPSIS
Remove Falcon Data Protection web locations
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Web location identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionLocation
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/web-locations/v2:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/web-locations/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionPattern {
<#
.SYNOPSIS
Remove Falcon Data Protection content patterns
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER Id
Content pattern identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionPattern
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/content-patterns/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/content-patterns/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
      Max = 100
    }
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
function Remove-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Remove Falcon Data Protection policies
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER PlatformName
Operating system
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDataProtectionPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/policies/v2:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('win','mac',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids','platform_name') }
      Max = 100
    }
    [hashtable]$Valid = @{}
    @((Get-Command $Param.Command).Parameters.PlatformName.Attributes.ValidValues).foreach{
      # Create hashtable of 'platform_name' lists to contain 'id' values
      $Valid[$_] = [System.Collections.Generic.List[string]]@()
    }
  }
  process { if ($PlatformName -and $Id) { $Valid.$PlatformName.Add($Id) }}
  end {
    @('Id','PlatformName').foreach{ [void]$PSBoundParameters.Remove($_) }
    foreach ($Pair in $Valid.GetEnumerator()) {
      # Delete in groups of 'platform_name' using 'id' lists
      $PSBoundParameters['platform_name'] = $Pair.Key
      $PSBoundParameters['ids'] = $Pair.Value
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
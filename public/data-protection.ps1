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
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ resources = @('classification_properties','id','name') }}
    }
  }
  process {
    if ($PSBoundParameters.ClassificationProperties) {
      # Filter 'classification_properties'
      $PSBoundParameters.ClassificationProperties = [PSCustomObject]$PSBoundParameters.ClassificationProperties |
        Select-Object content_patterns,evidence_duplication_enabled,file_types,protection_mode,rules,
        scan_profiles,sensitivity_labels,web_sources
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Modify a Falcon Data Protection policy
.DESCRIPTION
Requires 'Data Protection: Write'.
.PARAMETER PlatformName
Operating system
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
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDataProtectionPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/data-protection/entities/policies/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('win','mac',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('host_groups')]
    [object]$HostGroup,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('is_enabled')]
    [boolean]$IsEnabled,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('policy_properties')]
    [object]$PolicyProperties,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=8)]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          resources = @('description','host_groups','id','is_enabled','name','policy_properties','precedence')
        }
        Query = @('platform_name')
      }
    }
  }
  process {
    if ($PSBoundParameters.PolicyProperties) {
      @('custom_allow_notification','custom_block_notification').foreach{
        # Force 'custom_allow_notification' and 'custom_block_notification' to $null when empty [string]
        if ([string]::IsNullOrEmpty($PSBoundParameters.PolicyProperties.$_) -and $null -ne
        $PSBoundParameters.PolicyProperties.$_) {
          $PSBoundParameters.PolicyProperties.$_ = $null
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
function New-FalconDataProtectionClassification {
<#
.SYNOPSIS
Create a Falcon Data Protection classification
.DESCRIPTION
Requires 'Data Protection: Write'.
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
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/classifications/v2:post',
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('classification_properties')]
    [object]$ClassificationProperties
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ resources = @('classification_properties','name') }}
    }
  }
  process {
    if ($PSBoundParameters.ClassificationProperties) {
      # Filter 'classification_properties'
      $PSBoundParameters.ClassificationProperties = [PSCustomObject]$PSBoundParameters.ClassificationProperties |
        Select-Object content_patterns,evidence_duplication_enabled,file_types,protection_mode,rules,
        scan_profiles,sensitivity_labels,web_sources
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function New-FalconDataProtectionPolicy {
<#
.SYNOPSIS
Create a Falcon Data Protection policy
.DESCRIPTION
Requires 'Data Protection: Write'.
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
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('win','mac',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('policy_properties')]
    [object]$PolicyProperties
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ resources = @('description','name','policy_properties','precedence') }
        Query = @('platform_name')
      }
    }
  }
  process {
    if ($PSBoundParameters.PolicyProperties) {
      @('custom_allow_notification','custom_block_notification').foreach{
        # Force 'custom_allow_notification' and 'custom_block_notification' to $null when empty [string]
        if ([string]::IsNullOrEmpty($PSBoundParameters.PolicyProperties.$_) -and $null -ne
        $PSBoundParameters.PolicyProperties.$_) {
          $PSBoundParameters.PolicyProperties.$_ = $null
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
    [Alias('platform_name')]
    [string[]]$PlatformName,
    [Parameter(ParameterSetName='/data-protection/entities/policies/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
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
function Get-FalconCloudControl {
<#
.SYNOPSIS
Search for Falcon Cloud Security compliance controls
.DESCRIPTION
Requires 'Cloud Security Policies: Read'.
.PARAMETER Id
Compliance control identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudControl
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/queries/compliance/controls/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/compliance/controls/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get',Position=2)]
    [ValidateSet('compliance_control_authority|asc','compliance_control_authority|desc',
      'compliance_control_benchmark_name|asc','compliance_control_benchmark_name|desc',
      'compliance_control_benchmark_version|asc','compliance_control_benchmark_version|desc',
      'compliance_control_name|asc','compliance_control_name|desc','compliance_control_requirement|asc',
      'compliance_control_requirement|desc','compliance_control_section|asc','compliance_control_section|desc',
      'compliance_control_type|asc','compliance_control_type|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/controls/v1:get')]
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
function Get-FalconCloudFramework {
<#
.SYNOPSIS
Search for Falcon Cloud Security compliance frameworks
.DESCRIPTION
Requires 'Cloud Security Policies: Read'.
.PARAMETER Id
Compliance framework identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudFramework
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/compliance/frameworks/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get',Position=2)]
    [ValidateSet('compliance_framework_authority|asc','compliance_framework_authority|desc',
      'compliance_framework_name|asc','compliance_framework_name|desc','compliance_framework_version|asc',
      'compliance_framework_version|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-policies/queries/compliance/frameworks/v1:get')]
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
function Get-FalconCloudRule {
<#
.SYNOPSIS
Search for Falcon Cloud Security compliance rules
.DESCRIPTION
Requires 'Cloud Security Policies: Read'.
.PARAMETER Id
Compliance rule identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudRule
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/queries/rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get',Position=2)]
    [ValidateSet('rule_auto_remediable|asc','rule_auto_remediable|desc','rule_compliance_benchmark|asc',
      'rule_compliance_benchmark|desc','rule_compliance_framework|asc','rule_compliance_framework|desc',
      'rule_control_requirement|asc','rule_control_requirement|desc','rule_control_section|asc',
      'rule_control_section|desc','rule_created_at|asc','rule_created_at|desc','rule_description|asc',
      'rule_description|desc','rule_domain|asc','rule_domain|desc','rule_mitre_tactic|asc',
      'rule_mitre_tactic|desc','rule_mitre_technique|asc','rule_mitre_technique|desc','rule_name|asc',
      'rule_name|desc','rule_origin|asc','rule_origin|desc','rule_parent_uuid|asc','rule_parent_uuid|desc',
      'rule_provider|asc','rule_provider|desc','rule_resource_type|asc','rule_resource_type|desc',
      'rule_service|asc','rule_service|desc','rule_severity|asc','rule_severity|desc','rule_short_code|asc',
      'rule_short_code|desc','rule_status|asc','rule_status|desc','rule_subdomain|asc','rule_subdomain|desc',
      'rule_updated_at|asc','rule_updated_at|desc','rule_updated_by|asc','rule_updated_by|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-policies/queries/rules/v1:get')]
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
function Get-FalconCloudRuleOverride {
<#
.SYNOPSIS
Retrieve detail about Falcon Cloud Security compliance rule overrides
.DESCRIPTION
Requires 'Cloud Security Policies: Read'.
.PARAMETER Id
Compliance rule override identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudRuleOverride
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rule-overrides/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
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
function Remove-FalconCloudRule {
<#
.SYNOPSIS
Remove Falcon Cloud Security compliance rules
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Id
Compliance rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCloudRule
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rules/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
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
function Remove-FalconCloudRuleOverride {
<#
.SYNOPSIS
Remove Falcon Cloud Security compliance rule overrides
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Id
Compliance rule override identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCloudRuleOverride
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rule-overrides/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
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
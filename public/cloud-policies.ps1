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










function Edit-FalconCloudRule {
<#
.SYNOPSIS
Modify Falcon Cloud Security compliance rules
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Name
Compliance rule name
.PARAMETER Description
Compliance rule description
.PARAMETER Category
Compliance rule category
.PARAMETER Severity
Compliance rule severity
.PARAMETER RemediationInfo
Compliance rule remediation information
.PARAMETER RemediationUrl
Compliance rule remediation URL
.PARAMETER AlertInfo
Compliance rule alert information
.PARAMETER AttackType
Compliance rule attack type
.PARAMETER Control
Objects containing compliance rule control properties ('authority', 'code')
.PARAMETER RuleLogicList
Objects containing compliance rule logic properties ('logic', 'platform', 'remediation_info', 'remediation_url')
.PARAMETER Id
Compliance rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCloudRule
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rules/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Category,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('alert_info')]
    [string]$AlertInfo,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('attack_types')]
    [string[]]$AttackType,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('controls')]
    [object[]]$Control,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('rule_logic_list')]
    [object[]]$RuleLogicList,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=9)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('uuid')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('alert_info','attack_types','category','controls','description','name','rule_logic_list',
            'severity','uuid')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconCloudRule {
<#
.SYNOPSIS
Create Falcon Cloud Security compliance rules
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Domain
Compliance rule domain
.PARAMETER Subdomain
Compliance rule subdomain
.PARAMETER Name
Compliance rule name
.PARAMETER Description
Compliance rule description
.PARAMETER Severity
Compliance rule severity
.PARAMETER RemediationInfo
Compliance rule remediation information
.PARAMETER RemediationUrl
Compliance rule remediation URL
.PARAMETER ParentRuleId
Parent compliance rule identifier
.PARAMETER AlertInfo
Compliance rule alert information
.PARAMETER AttackType
Compliance rule attack type
.PARAMETER Provider
Compliance rule provider
.PARAMETER ResourceType
Compliance rule resource type
.PARAMETER Control
Objects containing compliance rule control properties ('authority', 'code')
.PARAMETER Logic
Compliance rule logic
.PARAMETER Platform
Compliance rule platform
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCloudRule
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rules/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Domain,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Subdomain,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Name,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [string]$Description,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('remediation_info')]
    [string]$RemediationInfo,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('remediation_url')]
    [string]$RemediationUrl,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('parent_rule_id','parent_rule_short_uuid')]
    [string]$ParentRuleId,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('alert_info')]
    [string]$AlertInfo,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('attack_types')]
    [string]$AttackType,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=11)]
    [string]$Provider,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=12)]
    [Alias('resource_type')]
    [string]$ResourceType,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=13)]
    [Alias('controls')]
    [object[]]$Control,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=14)]
    [string]$Logic,
    [Parameter(ParameterSetName='/cloud-policies/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=15)]
    [string]$Platform
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('alert_info','attack_types','controls','description','domain','logic','name','parent_rule_id',
            'platform','provider','remediation_info','remediation_url','resource_type','severity','subdomain')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconCloudRuleOverride {
<#
.SYNOPSIS
Update a rule override
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Crn

.PARAMETER ExpiresAt

.PARAMETER OverrideType

.PARAMETER OverridesDetails

.PARAMETER Reason

.PARAMETER Id

.PARAMETER TargetRegion

.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCloudRuleOverride
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Mandatory,Position=0)]
    [string]$Comment,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Mandatory,Position=0)]
    [string]$Crn,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Position=0)]
    [Alias('expires_at')]
    [datetime]$ExpiresAt,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Position=0)]
    [Alias('override_type')]
    [string]$OverrideType,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Position=0)]
    [Alias('overrides_details')]
    [string]$OverridesDetails,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Mandatory,Position=0)]
    [string]$Reason,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Position=0)]
    [Alias('rule_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:patch',Position=0)]
    [Alias('target_region')]
    [string]$TargetRegion
  )
  <#
  "overrides": [
    "comment",
    "crn",
    "expires_at",
    "override_type",
    "overrides_details",
    "reason",
    "rule_id",
    "target_region"
  ]
  #>
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconCloudRuleOverride {
<#
.SYNOPSIS
Create a new rule override
.DESCRIPTION
Requires 'Cloud Security Policies: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Crn

.PARAMETER ExpiresAt

.PARAMETER OverrideType

.PARAMETER OverridesDetails

.PARAMETER Reason

.PARAMETER RuleId

.PARAMETER TargetRegion

.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCloudRuleOverride
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Mandatory,Position=0)]
    [string]$Comment,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Mandatory,Position=0)]
    [string]$Crn,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Position=0)]
    [Alias('expires_at')]
    [datetime]$ExpiresAt,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Position=0)]
    [Alias('override_type')]
    [string]$OverrideType,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Position=0)]
    [Alias('overrides_details')]
    [string]$OverridesDetails,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Mandatory,Position=0)]
    [string]$Reason,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Position=0)]
    [Alias('rule_id')]
    [string]$RuleId,
    [Parameter(ParameterSetName='/cloud-policies/entities/rule-overrides/v1:post',Position=0)]
    [Alias('target_region')]
    [string]$TargetRegion
  )
  <#
  "overrides": [
    "comment",
    "crn",
    "expires_at",
    "override_type",
    "overrides_details",
    "reason",
    "rule_id",
    "target_region"
  ]
  #>
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
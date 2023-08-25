function Add-FalconFileVantageHostGroup {
<#
.SYNOPSIS
Assign host groups to FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconFileVantageHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      $PSBoundParameters['action'] = 'assign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Add-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Add rule groups to FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
FileVantage rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      $PSBoundParameters['action'] = 'assign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Edit-FalconFileVantagePolicy {
<#
.SYNOPSIS
Updates the general information of the provided policy.
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage policy identifier
.PARAMETER Name
Policy name
.PARAMETER Enabled
Policy enablement status
.PARAMETER Description
Policy description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFileVantagePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Enabled,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateLength(1,500)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconFileVantageChange {
<#
.SYNOPSIS
Search for Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
Activity identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageChange
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/queries/changes/v3:get',SupportsShouldProcess)]
  [Alias('Get-FalconFimChange')]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/changes/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('Ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get')]
    [string]$After,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get')]
    [switch]$Total
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
function Get-FalconFileVantageExclusion {
<#
.SYNOPSIS
List scheduled exclusions applied to a FileVantage policy
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
FileVantage scheduled exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/queries/policy-scheduled-exclusions/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/queries/policy-scheduled-exclusions/v1:get',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:get',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
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
function Get-FalconFileVantagePolicy {
<#
.SYNOPSIS
Search for FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
FileVantage policy identifier
.PARAMETER Type
Operating system type
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantagePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/queries/policies/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get',Mandatory,Position=1)]
    [ValidateSet('Linux','Mac','Windows',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get',Position=2)]
    [ValidateSet('created_timestamp|asc','created_timestamp|desc','modified_timestamp|asc',
      'modified_timestamp|desc','precedence|asc','precedence|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get')]
    [switch]$Total
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
function Get-FalconFileVantageRule {
<#
.SYNOPSIS
List FileVantage rules within a rule group
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER RuleGroupId
FileVantage rule group identifier
.PARAMETER Id
FileVantage rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageRule
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups-rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:get',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_id')]
    [string]$RuleGroupId,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Search for FileVantage rule groups
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
FileVantage rule group identifier
.PARAMETER Type
Rule group type
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/queries/rule-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get',Mandatory,Position=1)]
    [ValidateSet('LinuxFiles','MacFiles','WindowsFiles','WindowsRegistry',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get',Position=2)]
    [ValidateSet('created_timestamp|asc','created_timestamp|desc','modified_timestamp|asc',
      'modified_timestamp|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/filevantage/queries/rule-groups/v1:get')]
    [switch]$Total
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
function New-FalconFileVantagePolicy {
<#
.SYNOPSIS
Create FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Name
Policy name
.PARAMETER Platform
Operating system platform
.PARAMETER Description
Policy description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFileVantagePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',Mandatory,Position=1)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',Position=2)]
    [ValidateSet('Linux','Mac','Windows',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',Position=3)]
    [ValidateLength(1,500)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconFileVantageExclusion {
<#
.SYNOPSIS
Remove scheduled exclusions from FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
FileVantage scheduled exclusion identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantageExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:delete',Mandatory,
      Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFileVantageHostGroup {
<#
.SYNOPSIS
Remove host groups from FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantageHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      $PSBoundParameters['action'] = 'unassign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFileVantagePolicy {
<#
.SYNOPSIS
Remove FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantagePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFileVantageRule {
<#
.SYNOPSIS
Remove FileVantage rules from rule groups
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER RuleGroupId
FileVantage rule group identifier
.PARAMETER Id
FileVantage rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantageRule
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups-rules/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:delete',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_id')]
    [string]$RuleGroupId,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Remove or unassign FileVantage rule groups
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier, used when unassigning rule groups from a policy
.PARAMETER Id
FileVantage rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      if ($PSCmdlet.ParameterSetName -match 'patch$') { $PSBoundParameters['action'] = 'unassign' }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconFileVantagePrecedence {
<#
.SYNOPSIS
Set FileVantage policy precedence
.DESCRIPTION
All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to
define policy precedence.

Requires 'Falcon FileVantage: Write'.
.PARAMETER Type
Operating system type
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconFileVantagePrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-precedence/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-precedence/v1:patch',Mandatory,Position=1)]
    [ValidateSet('Linux','Mac','Windows',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/filevantage/entities/policies-precedence/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconFileVantageRulePrecedence {
<#
.SYNOPSIS
Set FileVantage rule precedence within a rule group
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER RuleGroupId
FileVantage rule group identifier
.PARAMETER Id
FileVantage rule identifiers in precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconFileVantageRulePrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups-rule-precedence/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rule-precedence/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_id')]
    [string]$RuleGroupId,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rule-precedence/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconFileVantageRuleGroupPrecedence {
<#
.SYNOPSIS
Set rule group precedence within FileVantage policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Id
FileVantage rule group identifiers in precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconFileVantageRuleGroupPrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      $PSBoundParameters['action'] = 'precedence'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
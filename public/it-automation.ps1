function Add-FalconItHostGroup {
<#
.SYNOPSIS
Assign host groups to Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER PolicyId
Policy identifier
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconItHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,Position=1)]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Alias('host_group_ids')]
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
      $PSBoundParameters['action'] = 'assign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconItFileTask {
<#
.SYNOPSIS
Search for Falcon for IT tasks associated with a given file
.DESCRIPTION
Requires 'IT Automation - Tasks: Read'.
.PARAMETER Id
File identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItFileTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/combined/associated-tasks/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [string]$Id,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=4)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconItPolicy {
<#
.SYNOPSIS
Search for Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Read'.
.PARAMETER Id
Policy identifier
.PARAMETER Platform
Operating system platform
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/queries/policies/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get',Mandatory,Position=1)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get',Position=2)]
    [ValidateSet('created_timestamp|asc','created_timestamp|desc','modified_timestamp|asc',
      'modified_timestamp|desc','precedence|asc','precedence|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/queries/policies/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }
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
function Get-FalconItScheduledTask {
<#
.SYNOPSIS
Search for Falcon for IT scheduled tasks
.DESCRIPTION
Requires 'IT Automation - Tasks: Read'.
.PARAMETER Id
Scheduled task identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItScheduledTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/queries/scheduled-tasks/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/scheduled-tasks/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get',Position=1)]
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get',Position=2)]
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get',Position=2)]
    [ValidateSet('created_by|asc','created_by|desc','created_time|asc','created_time|desc','end_time|asc',
      'end_time|desc','last_run|asc','last_run|desc','modified_by|asc','modified_by|desc','modified_time|asc',
      'modified_time|desc','start_time|asc','start_time|desc','task_id|asc','task_id|desc','task_name|asc',
      'task_name|desc','task_type|asc','task_type|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get',Position=3)]
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/scheduled-tasks/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/queries/scheduled-tasks/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }
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
function Get-FalconItTask {
<#
.SYNOPSIS
Search for Falcon for IT tasks
.DESCRIPTION
Requires 'IT Automation - Tasks: Read'.
.PARAMETER Id
Task identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/queries/tasks/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get',Position=1)]
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get',Position=2)]
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get',Position=2)]
    [ValidateSet('access_type|asc','access_type|desc','created_by|asc','created_by|desc','created_time|asc',
      'created_time|desc','modified_by|asc','modified_by|desc','modified_time|asc','modified_time|desc',
      'name|asc','name|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get',Position=3)]
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/tasks/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/queries/tasks/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }
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
function Get-FalconItTaskExecution {
<#
.SYNOPSIS
Search for Falcon for IT task executions
.DESCRIPTION
Requires 'IT Automation - Tasks Executions: Read'.
.PARAMETER Id
Task execution identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItTaskExecution
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/queries/task-executions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get',Position=1)]
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get',Position=2)]
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get',Position=2)]
    [ValidateSet('end_time|asc','end_time|desc','run_by|asc','run_by|desc','run_type|asc','run_type|desc',
      'start_time|asc','start_time|desc','status|asc','status|desc','task_id|asc','task_id|desc','task_name|asc',
      'task_name|desc','task_type|asc','task_type|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get',Position=3)]
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/task-executions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/queries/task-executions/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }
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
function Get-FalconItTaskGroup {
<#
.SYNOPSIS
Search for Falcon for IT task groups
.DESCRIPTION
Requires 'IT Automation - Tasks: Read'.
.PARAMETER Id
Task group identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItTaskGroup
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/queries/task-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-groups/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get',Position=1)]
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get',Position=2)]
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get',Position=2)]
    [ValidateSet('access_type|asc','access_type|desc','created_by|asc','created_by|desc','created_time|asc',
      'created_time|desc','modified_by|asc','modified_by|desc','modified_time|asc','modified_time|desc',
      'name|asc','name|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get',Position=3)]
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get')]
    [Parameter(ParameterSetName='/it-automation/combined/task-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/queries/task-groups/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 500 }
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
function Remove-FalconItHostGroup {
<#
.SYNOPSIS
Remove host groups from Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER PolicyId
Policy identifier
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconItHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,Position=1)]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Alias('host_group_ids')]
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
      $PSBoundParameters['action'] = 'unassign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconItPolicy {
<#
.SYNOPSIS
Remove Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconItPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
function Remove-FalconItScheduledTask {
<#
.SYNOPSIS
Remove Falcon for IT scheduled tasks
.DESCRIPTION
Requires 'IT Automation - Task Executions: Write'.
.PARAMETER Id
Scheduled task identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconItScheduledTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/scheduled-tasks/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/scheduled-tasks/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
function Remove-FalconItTask {
<#
.SYNOPSIS
Remove Falcon for IT tasks
.DESCRIPTION
Requires 'IT Automation - Tasks: Write'.
.PARAMETER Id
Task identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconItTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/tasks/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
function Remove-FalconItTaskGroup {
<#
.SYNOPSIS
Remove Falcon for IT task groups
.DESCRIPTION
Requires 'IT Automation - Tasks: Write'.
.PARAMETER Id
Task group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconItTaskGroup
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/task-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
function Set-FalconItPolicyPrecedence {
<#
.SYNOPSIS
Set Falcon for IT policy precedence
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER Platform
Operating system platform
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconItPolicyPrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies-precedence/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies-precedence/v1:patch',Mandatory,Position=1)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/it-automation/entities/policies-precedence/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
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
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
function Edit-FalconItPolicy {
<#
.SYNOPSIS
Modify Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Description of the policy
.PARAMETER Config
Policy settings
.PARAMETER Enabled
Policy enablement status
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconItPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [object]$Config,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [Alias('is_enabled')]
    [boolean]$Enabled
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('config','description','id','is_enabled','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconItTask {
<#
.SYNOPSIS
Modify Falcon for IT tasks
.DESCRIPTION
Requires 'IT Automation - Tasks: Write'.
.PARAMETER Name
Task name
.PARAMETER Description
Task description
.PARAMETER TaskType
Task type
.PARAMETER AccessType
Task access type
.PARAMETER Target
Falcon Query Language expression to define target hosts
.PARAMETER Parameter
Task parameters ('key', 'label', 'input_type')
.PARAMETER Query
Query parameters by operating system ('action_type', 'content', 'file_ids', 'language', 'script_args',
'script_file_id')
.PARAMETER Remediation
Remediation parameters by operating system
.PARAMETER Trigger
Trigger condition
.PARAMETER Verification
Verification condition
.PARAMETER OsQuery
OsQuery statement
.PARAMETER TaskGroupId
Task group identifier
.PARAMETER AddUserGroupId
User group identifier to add
.PARAMETER AddUserId
User identifier to add
.PARAMETER RemoveUserGroupId
User group identifier to remove
.PARAMETER RemoveUserId
User identifier to remove
.PARAMETER OutputParser
Column and delimiter values to parse result output
.PARAMETER Id
Task identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconItTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/tasks/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidateSet('query','remediation',IgnoreCase=$false)]
    [Alias('task_type')]
    [string]$TaskType,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateSet('Public','Shared',IgnoreCase=$false)]
    [Alias('access_type')]
    [string]$AccessType,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Target,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('task_parameters')]
    [object[]]$Parameter,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('queries')]
    [object]$Query,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('remediations')]
    [object]$Remediation,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('trigger_condition')]
    [object[]]$Trigger,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('verification_condition')]
    [object[]]$Verification,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=11)]
    [Alias('os_query')]
    [string]$OsQuery,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=12)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('task_group_id')]
    [string]$TaskGroupId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',Position=13)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('add_assigned_user_group_ids')]
    [string[]]$AddUserGroupId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',Position=14)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('add_assigned_user_ids')]
    [string[]]$AddUserId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',Position=15)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('remove_assigned_user_group_ids')]
    [string[]]$RemoveUserGroupId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',Position=16)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('remove_assigned_user_ids')]
    [string[]]$RemoveUserId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',ValueFromPipelineByPropertyName,
      Position=17)]
    [Alias('output_parser_config')]
    [object]$OutputParser,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=18)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('access_type','add_assigned_user_group_ids','add_assigned_user_ids','description','name',
            'os_query','output_parser_config','queries','remediations','remove_assigned_user_group_ids',
            'remove_assigned_user_ids','target','task_group_id','task_parameters','task_type','trigger_condition',
            'verification_condition')
        }
        Query = @('id')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
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
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/combined/associated-tasks/v1:get',Position=4)]
    [ValidateRange(1,500)]
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
function Get-FalconItHostExecution {
<#
.SYNOPSIS
Search for host results of Falcon for IT task executions
.DESCRIPTION
Requires 'IT Automation - Task Executions: Read'.
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
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconItHostExecution
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/task-execution-host-status/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get',Position=3)]
    [ValidateSet('end_time|asc','end_time|desc','start_time|asc','start_time|desc','status|asc','status|desc',
      'total_results|asc','total_results|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get',Position=4)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-host-status/v1:get')]
    [switch]$Total
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    [ValidateRange(1,500)]
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    [ValidateRange(1,500)]
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    [ValidateRange(1,500)]
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
    [ValidateRange(1,500)]
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
function Invoke-FalconItTask {
<#
.SYNOPSIS
Initiate an existing Falcon for IT task, or create and run a task on target hosts
.DESCRIPTION
Requires 'IT Automation - Task Executions: Write'.
.PARAMETER Id
Task identifier
.PARAMETER Target
Falcon Query Language expression to define target hosts
.PARAMETER Query
Query parameters by operating system ('action_type', 'content', 'file_ids', 'language', 'script_args',
'script_file_id')
.PARAMETER ExecutionArg
Key/value pairs to define arguments during execution of an existing task
.PARAMETER OsQuery
OsQuery statement
.PARAMETER DiscoverOffline
Discover offline hosts
.PARAMETER DiscoverNew
Discover new hosts
.PARAMETER Guardrail
Execution guardrails and limits
.PARAMETER Distribute
Distribute task
.PARAMETER OutputParser
Specifies columns and delimiter for parsing script execution results
.PARAMETER ExpirationInterval
Interval before task expires. Once expired, new and offline hosts won't be targeted
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconItTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/task-executions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('task_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Mandatory,Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Target,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=2)]
    [Alias('queries')]
    [object]$Query,
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=3)]
    [Alias('execution_args')]
    [object]$ExecutionArg,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=3)]
    [string]$OsQuery,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=4)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=4)]
    [Alias('discover_offline_hosts')]
    [boolean]$DiscoverOffline,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=5)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=5)]
    [Alias('discover_new_hosts')]
    [boolean]$DiscoverNew,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=6)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=6)]
    [Alias('guardrails')]
    [object]$Guardrail,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=7)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=7)]
    [boolean]$Distribute,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=8)]
    [Alias('output_parser_config')]
    [object]$OutputParser,
    [Parameter(ParameterSetName='/it-automation/entities/live-query-execution/v1:post',Position=9)]
    [Parameter(ParameterSetName='/it-automation/entities/task-executions/v1:post',Position=8)]
    [Alias('expiration_interval')]
    [string]$ExpirationInterval
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = if ($PSCmdlet.ParameterSetName -match 'live-query-execution') {
            @('discover_new_hosts','discover_offline_hosts','distribute','expiration_interval','guardrails',
              'osquery','output_parser_config','target','queries')
          } else {
            @('discover_new_hosts','discover_offline_hosts','distribute','execution_args','expiration_interval',
              'guardrails','target','task_id')
          }
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconItPolicy {
<#
.SYNOPSIS
Create Falcon for IT policies
.DESCRIPTION
Requires 'IT Automation - Policies: Write'.
.PARAMETER Name
Policy name
.PARAMETER Platform
Operating system platform
.PARAMETER Description
Description of the policy
.PARAMETER Config
Policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconItPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/policies/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/it-automation/entities/policies/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [object]$Config
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('config','description','name','platform') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconItTask {
<#
.SYNOPSIS
Create Falcon for IT tasks
.DESCRIPTION
Requires 'IT Automation - Tasks: Write'.
.PARAMETER Name
Task name
.PARAMETER Description
Task description
.PARAMETER TaskType
Task type
.PARAMETER AccessType
Task access type
.PARAMETER Target
Falcon Query Language expression to define target hosts
.PARAMETER Parameter
Task parameters ('key', 'label', 'input_type')
.PARAMETER Query
Query parameters by operating system ('action_type', 'content', 'file_ids', 'language', 'script_args',
'script_file_id')
.PARAMETER Remediation
Remediation parameters by operating system
.PARAMETER Trigger
Trigger condition
.PARAMETER Verification
Verification condition
.PARAMETER OsQuery
OsQuery statement
.PARAMETER TaskGroupId
Task group identifier
.PARAMETER UserGroupId
User group identifier (for 'Shared' AccessType)
.PARAMETER UserId
User identifier (for 'Shared' AccessType)
.PARAMETER OutputParser
Column and delimiter values to parse result output
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconItTask
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/tasks/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidateSet('query','remediation',IgnoreCase=$false)]
    [Alias('task_type')]
    [string]$TaskType,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateSet('Public','Shared',IgnoreCase=$false)]
    [Alias('access_type')]
    [string]$AccessType,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Target,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('task_parameters')]
    [object[]]$Parameter,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('queries')]
    [object]$Query,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('remediations')]
    [object]$Remediation,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('trigger_condition')]
    [object[]]$Trigger,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('verification_condition')]
    [object[]]$Verification,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=11)]
    [Alias('os_query')]
    [string]$OsQuery,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=12)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('task_group_id')]
    [string]$TaskGroupId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=13)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('assigned_user_group_ids')]
    [string[]]$UserGroupId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=14)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('assigned_user_ids')]
    [string[]]$UserId,
    [Parameter(ParameterSetName='/it-automation/entities/tasks/v1:post',ValueFromPipelineByPropertyName,
      Position=15)]
    [Alias('output_parser_config')]
    [object]$OutputParser
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('access_type','assigned_user_group_ids','assigned_user_ids','description','name','os_query',
            'output_parser_config','queries','remediations','target','task_group_id','task_parameters',
            'task_type','trigger_condition','verification_condition')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/it-automation/entities/policies-host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Stop-FalconItTaskExecution {
<#
.SYNOPSIS
Cancel a Falcon for IT task execution
.DESCRIPTION
Requires 'IT Automation - Task Executions: Write'.
.PARAMETER Id
Task execution identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Stop-FalconItTaskExecution
#>
  [CmdletBinding(DefaultParameterSetName='/it-automation/entities/task-execution-cancel/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/it-automation/entities/task-execution-cancel/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('task_execution_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
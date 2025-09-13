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
      $PSBoundParameters['Id'] = @($List)
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
      $PSBoundParameters['Id'] = @($List)
      $PSBoundParameters['action'] = 'assign'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Edit-FalconFileVantageExclusion {
<#
.SYNOPSIS
Modify scheduled exclusions within a FileVantage policy
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage scheduled exclusion identifier
.PARAMETER PolicyId
FileVantage policy identifier
.PARAMETER Name
Scheduled exclusion name
.PARAMETER ScheduleStart
Start of scheduled exclusion (RFC3339)
.PARAMETER ScheduleEnd
End of scheduled exclusion (RFC3339)
.PARAMETER Timezone
Timezone for scheduled start/end time (TZ database format)
.PARAMETER Repeated
Object containing properties for repeating exclusion based on scheduled start/end time ('all_day', 'end_time',
'frequency', 'monthly_days', 'occurrence', 'start_time', and 'weekly_days')
.PARAMETER Process
One or more process names in glob syntax, separated by commas
.PARAMETER User
One or more user names in glob syntax, separated by commas
.PARAMETER Description
Scheduled exclusion description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFileVantageExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('schedule_start')]
    [string]$ScheduleStart,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=5)]
    [Alias('schedule_end')]
    [string]$ScheduleEnd,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=6)]
    [string]$Timezone,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=7)]
    [object]$Repeated,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=8)]
    [ValidateLength(0,500)]
    [Alias('processes')]
    [string]$Process,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=9)]
    [ValidateLength(0,500)]
    [Alias('users')]
    [string]$User,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:patch',
      ValueFromPipelineByPropertyName,Position=10)]
    [ValidateLength(0,500)]
    [string]$Description
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Format
  }
  process {
    if ($PSBoundParameters.Repeated) {
      # Filter to defined 'repeated' properties and make sure 'repeated' is properly appended
      $PSBoundParameters.Repeated = [PSCustomObject]$PSBoundParameters.Repeated |
        Select-Object $Param.Format.Body.repeated
      [void]$Param.Format.Body.Remove('repeated')
      $Param.Format.Body.root += 'repeated'
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconFileVantagePolicy {
<#
.SYNOPSIS
Modify FileVantage policies
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
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateLength(0,500)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconFileVantageRule {
<#
.SYNOPSIS
Modify a rule within a FileVantage rule group
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
Rule identifier
.PARAMETER Precedence
Precedence of the rule inside of the existing rule group
.PARAMETER Path
Path of the directory, file, or registry key to monitor
.PARAMETER Depth
Monitoring depth below the initial target directory/file/registry key
.PARAMETER Severity
Rule severity
.PARAMETER Description
Rule description
.PARAMETER Include
Directories, files, registry keys and/or registry values to monitor, separated by commas
.PARAMETER Exclude
Directories, files, registry keys and/or registry values to exclude, separated by commas
.PARAMETER IncludeProcess
Restrict monitoring to changes made by one or more processes
.PARAMETER ExcludeProcess
Exclude changes made by one or more processes
.PARAMETER IncludeUser
Restrict monitoring to changes made by one or more users
.PARAMETER ExcludeUser
Exclude changes made by one or more users
.PARAMETER DirectoryAttribute
Track directory attribute change events
.PARAMETER DirectoryCreate
Track directory create events
.PARAMETER DirectoryDelete
Track directory delete events
.PARAMETER DirectoryPermission
Track directory permission change events
.PARAMETER DirectoryRename
Track directory rename events
.PARAMETER FileAttribute
Track file attribute change events
.PARAMETER FileChange
Track file change events
.PARAMETER FileDelete
Track file delete events
.PARAMETER FilePermission
Track file permission change events
.PARAMETER FileRename
Track file rename events
.PARAMETER FileWrite
Track file write events
.PARAMETER RegKeyCreate
Track registry key create events
.PARAMETER RegKeyDelete
Track registry key delete events
.PARAMETER RegKeyPermission
Track registry key permission change events
.PARAMETER RegKeyRename
Track registry key rename events
.PARAMETER RegKeySet
Track registry key set events
.PARAMETER RegValueCreate
Track registry value create events
.PARAMETER RegValueDelete
Track registry value delete events
.PARAMETER EnableContentCapture
Enable the capture of file content during events
.PARAMETER ContentFiles
A specific list of files to monitor for content changes
.PARAMETER ContentRegistryValues
A specific list of registry paths to monitor for content changes (matching Include/Exclude)
.PARAMETER HashCapture
Track file hash
.PARAMETER RuleGroupId
FileVantage rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFileVantageRule
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidateLength(1,250)]
    [string]$Path,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateSet('1','2','3','4','5','ANY',IgnoreCase=$false)]
    [string]$Depth,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidateSet('Low','Medium','High','Critical',IgnoreCase=$false)]
    [string]$Severity,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [ValidateLength(0,500)]
    [string]$Description,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [string]$Include,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [string]$Exclude,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('include_processes')]
    [string]$IncludeProcess,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('exclude_processes')]
    [string]$ExcludeProcess,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=11)]
    [Alias('include_users')]
    [string]$IncludeUser,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=12)]
    [Alias('exclude_users')]
    [string]$ExcludeUser,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=13)]
    [Alias('watch_attributes_directory_changes')]
    [boolean]$DirectoryAttribute,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=14)]
    [Alias('watch_create_directory_changes')]
    [boolean]$DirectoryCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=15)]
    [Alias('watch_delete_directory_changes')]
    [boolean]$DirectoryDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=16)]
    [Alias('watch_permissions_directory_changes')]
    [boolean]$DirectoryPermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=17)]
    [Alias('watch_rename_directory_changes')]
    [boolean]$DirectoryRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=18)]
    [Alias('watch_attributes_file_changes')]
    [boolean]$FileAttribute,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=19)]
    [Alias('watch_create_file_changes')]
    [boolean]$FileChange,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=20)]
    [Alias('watch_delete_file_changes')]
    [boolean]$FileDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=21)]
    [Alias('watch_permissions_file_changes')]
    [boolean]$FilePermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=22)]
    [Alias('watch_rename_file_changes')]
    [boolean]$FileRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=23)]
    [Alias('watch_write_file_changes')]
    [boolean]$FileWrite,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=24)]
    [Alias('watch_create_key_changes')]
    [boolean]$RegKeyCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=25)]
    [Alias('watch_delete_key_changes')]
    [boolean]$RegKeyDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=26)]
    [Alias('watch_permissions_key_changes')]
    [boolean]$RegKeyPermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=27)]
    [Alias('watch_rename_key_changes')]
    [boolean]$RegKeyRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=28)]
    [Alias('watch_set_value_changes')]
    [boolean]$RegKeySet,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=29)]
    [Alias('watch_create_value_changes')]
    [boolean]$RegValueCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=30)]
    [Alias('watch_delete_value_changes')]
    [boolean]$RegValueDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=31)]
    [Alias('enable_content_capture')]
    [boolean]$EnableContentCapture,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=32)]
    [Alias('content_files')]
    [string[]]$ContentFiles,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=33)]
    [Alias('content_registry_values')]
    [string[]]$ContentRegistryValues,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=34)]
    [Alias('enable_hash_capture')]
    [boolean]$HashCapture,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_id')]
    [string]$RuleGroupId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Modify FileVantage rule groups
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage rule group identifier
.PARAMETER Name
Rule group name
.PARAMETER Description
Rule group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:patch',Position=2)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:patch',Position=3)]
    [ValidateLength(0,500)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconFileVantageAction {
<#
.SYNOPSIS
Search for Falcon FileVantage actions
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
FileVantage action identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageAction
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/queries/actions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/actions/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/filevantage/queries/actions/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) } } else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFileVantageChange {
<#
.SYNOPSIS
Search for Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
FileVantage change identifier
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
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=2)]
    [ValidateSet('action_timestamp|asc','action_timestamp|desc','ingestion_timestamp|asc',
      'ingestion_timestamp|desc',IgnoreCase=$false)]
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
function Get-FalconFileVantageContent {
<#
.SYNOPSIS
Retrieve content recorded in a Falcon FileVantage change
.DESCRIPTION
Requires 'Falcon FileVantage Content: Read'.
.PARAMETER Id
FileVantage change identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFileVantageContent
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/change-content/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/change-content/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
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
.PARAMETER Include
Include additional properties
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
    [Parameter(ParameterSetName='/filevantage/queries/policies/v1:get',Position=4)]
    [ValidateSet('exclusions',IgnoreCase=$false)]
    [string[]]$Include,
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
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    if ($Include) {
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
      if ($Request -and $Include -contains 'exclusions') {
        if (!$Request.id) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ id = $_ } }}
        foreach ($i in $Request) {
          $Exclusion = Get-FalconFileVantageExclusion -PolicyId $i.id -EA 0
          if ($Exclusion -and $PSBoundParameters.Detailed) {
            $Exclusion = $Exclusion | Get-FalconFileVantageExclusion -PolicyId $i.id
          }
          Set-Property $i exclusions $Exclusion
        }
      }
      $Request
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
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
      $PSBoundParameters['Id'] = @($List)
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
function Invoke-FalconFileVantageAction {
<#
.SYNOPSIS
Perform actions on Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Comment
Audit log comment
.PARAMETER Id
FileVantage change identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconFileVantageAction
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('suppress','unsuppress','purge',IgnoreCase=$false)]
    [Alias('operation')]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/actions/v1:post',Position=2)]
    [string]$Comment,
    [Parameter(ParameterSetName='/filevantage/entities/actions/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=3)]
    [Alias('change_ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 100 }
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
function Invoke-FalconFileVantageWorkflow {
<#
.SYNOPSIS
Execute an on-demand Falcon Fusion workflow for Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage change identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconFileVantageWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/workflow/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/workflow/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Mandatory,Position=1)]
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
function New-FalconFileVantageExclusion {
<#
.SYNOPSIS
Create a scheduled exclusion within a FileVantage policy
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Name
Scheduled exclusion name
.PARAMETER ScheduleStart
Start of scheduled exclusion (RFC3339)
.PARAMETER ScheduleEnd
End of scheduled exclusion (RFC3339)
.PARAMETER Timezone
Timezone for scheduled start/end time (TZ database format)
.PARAMETER Repeated
Object containing properties for repeating exclusion based on scheduled start/end time ('all_day', 'end_time',
'frequency', 'monthly_days', 'occurrence', 'start_time', and 'weekly_days')
.PARAMETER Process
One or more process names in glob syntax, separated by commas
.PARAMETER User
One or more user names in glob syntax, separated by commas
.PARAMETER Description
Scheduled exclusion description
.PARAMETER PolicyId
FileVantage policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFileVantageExclusion
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('schedule_start')]
    [string]$ScheduleStart,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('schedule_end')]
    [string]$ScheduleEnd,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=4)]
    [string]$Timezone,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=5)]
    [object]$Repeated,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=6)]
    [ValidateLength(0,500)]
    [Alias('processes')]
    [string]$Process,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=7)]
    [ValidateLength(0,500)]
    [Alias('users')]
    [string]$User,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',
      ValueFromPipelineByPropertyName,Position=8)]
    [ValidateLength(0,500)]
    [string]$Description,
    [Parameter(ParameterSetName='/filevantage/entities/policy-scheduled-exclusions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=9)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Format
  }
  process {
    if ($PSBoundParameters.Repeated) {
      # Filter to defined 'repeated' properties and make sure 'repeated' is properly appended
      $PSBoundParameters.Repeated = [PSCustomObject]$PSBoundParameters.Repeated |
        Select-Object $Param.Format.Body.repeated
      [void]$Param.Format.Body.Remove('repeated')
      $Param.Format.Body.root += 'repeated'
    }
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
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidateSet('Linux','Mac','Windows',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/filevantage/entities/policies/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidateLength(0,500)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconFileVantageRule {
<#
.SYNOPSIS
Create a rule within a FileVantage rule group
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Precedence
Precedence for the new rule inside of the existing rule group
.PARAMETER Path
Path of the directory, file, or registry key to monitor
.PARAMETER Depth
Monitoring depth below the initial target directory/file/registry key
.PARAMETER Severity
Rule severity
.PARAMETER Description
Rule description
.PARAMETER Include
Directories, files, registry keys and/or registry values to monitor, separated by commas
.PARAMETER Exclude
Directories, files, registry keys and/or registry values to exclude, separated by commas
.PARAMETER IncludeProcess
Restrict monitoring to changes made by one or more processes
.PARAMETER ExcludeProcess
Exclude changes made by one or more processes
.PARAMETER IncludeUser
Restrict monitoring to changes made by one or more users
.PARAMETER ExcludeUser
Exclude changes made by one or more users
.PARAMETER DirectoryAttribute
Track directory attribute change events
.PARAMETER DirectoryCreate
Track directory create events
.PARAMETER DirectoryDelete
Track directory delete events
.PARAMETER DirectoryPermission
Track directory permission change events
.PARAMETER DirectoryRename
Track directory rename events
.PARAMETER FileAttribute
Track file attribute change events
.PARAMETER FileChange
Track file change events
.PARAMETER FileDelete
Track file delete events
.PARAMETER FilePermission
Track file permission change events
.PARAMETER FileRename
Track file rename events
.PARAMETER FileWrite
Track file write events
.PARAMETER RegKeyCreate
Track registry key create events
.PARAMETER RegKeyDelete
Track registry key delete events
.PARAMETER RegKeyPermission
Track registry key permission change events
.PARAMETER RegKeyRename
Track registry key rename events
.PARAMETER RegKeySet
Track registry key set events
.PARAMETER RegValueCreate
Track registry value create events
.PARAMETER RegValueDelete
Track registry value delete events
.PARAMETER EnableContentCapture
Enable the capture of file content during events
.PARAMETER ContentFiles
A specific list of files to monitor for content changes
.PARAMETER ContentRegistryValues
A specific list of registry paths to monitor for content changes (matching Include/Exclude)
.PARAMETER HashCapture
Track file hash
.PARAMETER RuleGroupId
FileVantage rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFileVantageRule
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [int32]$Precedence,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateLength(1,250)]
    [string]$Path,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidateSet('1','2','3','4','5','ANY',IgnoreCase=$false)]
    [string]$Depth,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidateSet('Low','Medium','High','Critical',IgnoreCase=$false)]
    [string]$Severity,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidateLength(0,500)]
    [string]$Description,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [string]$Include,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [string]$Exclude,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=8)]
    [Alias('include_processes')]
    [string]$IncludeProcess,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('exclude_processes')]
    [string]$ExcludeProcess,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('include_users')]
    [string]$IncludeUser,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=11)]
    [Alias('exclude_users')]
    [string]$ExcludeUser,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=12)]
    [Alias('watch_attributes_directory_changes')]
    [boolean]$DirectoryAttribute,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=13)]
    [Alias('watch_create_directory_changes')]
    [boolean]$DirectoryCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=14)]
    [Alias('watch_delete_directory_changes')]
    [boolean]$DirectoryDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=15)]
    [Alias('watch_permissions_directory_changes')]
    [boolean]$DirectoryPermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=16)]
    [Alias('watch_rename_directory_changes')]
    [boolean]$DirectoryRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=17)]
    [Alias('watch_attributes_file_changes')]
    [boolean]$FileAttribute,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=18)]
    [Alias('watch_create_file_changes')]
    [boolean]$FileChange,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=19)]
    [Alias('watch_delete_file_changes')]
    [boolean]$FileDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=20)]
    [Alias('watch_permissions_file_changes')]
    [boolean]$FilePermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=21)]
    [Alias('watch_rename_file_changes')]
    [boolean]$FileRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=22)]
    [Alias('watch_write_file_changes')]
    [boolean]$FileWrite,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=23)]
    [Alias('watch_create_key_changes')]
    [boolean]$RegKeyCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=24)]
    [Alias('watch_delete_key_changes')]
    [boolean]$RegKeyDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=25)]
    [Alias('watch_permissions_key_changes')]
    [boolean]$RegKeyPermission,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=26)]
    [Alias('watch_rename_key_changes')]
    [boolean]$RegKeyRename,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=27)]
    [Alias('watch_set_value_changes')]
    [boolean]$RegKeySet,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=28)]
    [Alias('watch_create_value_changes')]
    [boolean]$RegValueCreate,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=29)]
    [Alias('watch_delete_value_changes')]
    [boolean]$RegValueDelete,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=30)]
    [Alias('enable_content_capture')]
    [boolean]$EnableContentCapture,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=31)]
    [Alias('content_files')]
    [string[]]$ContentFiles,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=32)]
    [Alias('content_registry_values')]
    [string[]]$ContentRegistryValues,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',ValueFromPipelineByPropertyName,
      Position=33)]
    [Alias('enable_hash_capture')]
    [boolean]$HashCapture,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups-rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_id')]
    [string]$RuleGroupId
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Create FileVantage rule groups
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Type
Rule group type
.PARAMETER Name
Rule group name
.PARAMETER Description
Rule group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('LinuxFiles','MacFiles','WindowsFiles','WindowsRegistry',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateLength(1,100)]
    [string]$Name,
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:post',
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateLength(0,500)]
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
      $PSBoundParameters['Id'] = @($List)
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
      $PSBoundParameters['Id'] = @($List)
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
      $PSBoundParameters['Id'] = @($List)
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFileVantageRuleGroup {
<#
.SYNOPSIS
Remove FileVantage rule groups or unassign them from policies
.DESCRIPTION
Requires 'Falcon FileVantage: Write'.
.PARAMETER Id
FileVantage rule group identifier
.PARAMETER PolicyId
FileVantage policy identifier, used when unassigning rule groups from a policy
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFileVantageRuleGroup
#>
  [CmdletBinding(DefaultParameterSetName='/filevantage/entities/rule-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id')]
    [string]$PolicyId,
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,Position=2)]
    [Parameter(ParameterSetName='/filevantage/entities/rule-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','rule_groups')]
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
All policy identifiers must be supplied in order (including the default policy) to define policy precedence.

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
    [Parameter(ParameterSetName='/filevantage/entities/policies-precedence/v1:patch',Mandatory,ValueFromPipeline,
      Position=2)]
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
      ValueFromPipeline,Position=2)]
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
    [Parameter(ParameterSetName='/filevantage/entities/policies-rule-groups/v1:patch',Mandatory,ValueFromPipeline,
      Position=2)]
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
      $PSBoundParameters['action'] = 'precedence'
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
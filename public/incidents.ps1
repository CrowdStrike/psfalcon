function Get-FalconBehavior {
<#
.SYNOPSIS
Search for behaviors
.DESCRIPTION
Requires 'Incidents: Read'.
.PARAMETER Id
Behavior identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconBehavior
#>
  [CmdletBinding(DefaultParameterSetName='/incidents/queries/behaviors/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/incidents/entities/behaviors/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^ind:[a-fA-F0-9]{32}:(\d|\-)+$')]
    [Alias('ids','behavior_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=2)]
    [ValidateSet('timestamp.asc','timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/incidents/queries/behaviors/v1:get')]
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
function Get-FalconIncident {
<#
.SYNOPSIS
Search for incidents
.DESCRIPTION
Requires 'Incidents: Read'.
.PARAMETER Id
Incident identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIncident
#>
  [CmdletBinding(DefaultParameterSetName='/incidents/queries/incidents/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/incidents/entities/incidents/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^inc:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$')]
    [Alias('ids','incident_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=2)]
    [ValidateSet('assigned_to.asc','assigned_to.desc','assigned_to_name.asc','assigned_to_name.desc',
      'end.asc','end.desc','modified_timestamp.asc','modified_timestamp.desc','name.asc','name.desc',
      'sort_score.asc','sort_score.desc','start.asc','start.desc','state.asc','state.desc',
      'status.asc','status.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/incidents/queries/incidents/v1:get')]
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
function Get-FalconScore {
<#
.SYNOPSIS
Search for CrowdScore values
.DESCRIPTION
Requires 'Incidents: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScore
#>
  [CmdletBinding(DefaultParameterSetName='/incidents/combined/crowdscores/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=2)]
    [ValidateSet('score.asc','score.desc','timestamp.asc','timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get',Position=3)]
    [ValidateRange(1,2500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/incidents/combined/crowdscores/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Invoke-FalconIncidentAction {
<#
.SYNOPSIS
Perform actions on incidents
.DESCRIPTION
Requires 'Incidents: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Value
Value for the chosen action
.PARAMETER Action
One or more hashtables defining multiple name/value pairs
.PARAMETER UpdateDetects
Update status of related 'new' detections
.PARAMETER OverwriteDetects
Replace existing status for related detections
.PARAMETER Id
Incident identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconIncidentAction
#>
  [CmdletBinding(DefaultParameterSetName='/incidents/entities/incident-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('add_tag','delete_tag','unassign','update_description','update_name','update_status',
      'update_assigned_to_v2',IgnoreCase=$false)]
    [string]$Name,
    [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Position=2)]
    [string]$Value,
    [Parameter(ParameterSetName='action_parameters',Mandatory,Position=1)]
    [Alias('action_parameters')]
    [hashtable[]]$Action,
    [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Position=3)]
    [Parameter(ParameterSetName='action_parameters',Position=2)]
    [Alias('update_detects')]
    [boolean]$UpdateDetects,
    [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Position=4)]
    [Parameter(ParameterSetName='action_parameters',Position=3)]
    [Alias('overwrite_detects')]
    [boolean]$OverwriteDetects,
    [Parameter(ParameterSetName='/incidents/entities/incident-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
    [Parameter(ParameterSetName='action_parameters',Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,
      Position=4)]
    [ValidatePattern('^inc:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$')]
    [Alias('ids','incident_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/incidents/entities/incident-actions/v1:post'
      Max = 1000
    }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      if ($PSBoundParameters.Action) {
        # Verify valid 'Action' key/value pairs and update formatting before request
        $Valid = (Get-Command $Param.Command).Parameters.Name.Attributes.ValidValues
        [hashtable[]]$PSBoundParameters.Action = @($PSBoundParameters.Action).foreach{
          Test-ActionParameter $_ $Valid -Incident
        }
        $Param.Format.Body.root = @('ids','action_parameters')
        [void]$Param.Format.Body.Remove('action_parameters')
      } else {
        # Update 'value' when 'name' is 'update_status'
        $Valid = Test-ActionParameter @{ $PSBoundParameters.Name = $PSBoundParameters.Value } -Incident
        if ($Valid -and $PSBoundParameters.Value -ne $Valid.Value) { $PSBoundParameters.Value = $Valid.Value }
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
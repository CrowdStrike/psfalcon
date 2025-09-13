function Get-FalconAlert {
<#
.SYNOPSIS
Search for alerts
.DESCRIPTION
Requires 'Alerts: Read'.
.PARAMETER Id
Alert identifier
.PARAMETER IncludeHidden
Include hidden alerts when retrieving results by identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconAlert
#>
  [CmdletBinding(DefaultParameterSetName='/alerts/queries/alerts/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/alerts/entities/alerts/v2:post',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('composite_ids','composite_id','ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/alerts/entities/alerts/v2:post',Position=1)]
    [Alias('include_hidden')]
    [boolean]$IncludeHidden,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get',Position=1)]
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post',Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get',Position=3)]
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get',Position=4)]
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post',Position=3)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post')]
    [string]$After,
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get')]
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post')]
    [switch]$All,
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get')]
    [Parameter(ParameterSetName='/alerts/combined/alerts/v1:post')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
    if ($PSCmdlet.ParameterSetName -eq '/alerts/combined/alerts/v1:post') {
      # Enforce maximum limit for '/alerts/combined/alerts/v1:post'
      if ($PSBoundParameters.Limit -and $PSBoundParameters.Limit -gt 1000) { $PSBoundParameters['Limit'] = 1000 }
    }
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['composite_ids'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Invoke-FalconAlertAction {
<#
.SYNOPSIS
Perform actions on alerts
.DESCRIPTION
Requires 'Alerts: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Value
Value for the chosen action
.PARAMETER Action
One or more hashtables defining multiple name/value pairs
.PARAMETER IncludeHidden
Include hidden alerts when performing action [default: $true]
.PARAMETER Id
Alert identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconAlertAction
#>
  [CmdletBinding(DefaultParameterSetName='/alerts/entities/alerts/v3:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/alerts/entities/alerts/v3:patch',Mandatory,Position=1)]
    [ValidateSet('add_tag','append_comment','assign_to_name','assign_to_user_id','assign_to_uuid',
      'remove_tag','remove_tags_by_prefix','show_in_ui','unassign','update_status',IgnoreCase=$false)]
    [string]$Name,
    [Parameter(ParameterSetName='/alerts/entities/alerts/v3:patch',Position=2)]
    [string]$Value,
    [Parameter(ParameterSetName='action_parameters',Mandatory,Position=1)]
    [Alias('action_parameters')]
    [hashtable[]]$Action,
    [Parameter(ParameterSetName='/alerts/entities/alerts/v3:patch',Position=3)]
    [Parameter(ParameterSetName='action_parameters',Position=2)]
    [Alias('include_hidden')]
    [boolean]$IncludeHidden,
    [Parameter(ParameterSetName='/alerts/entities/alerts/v3:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=3)]
    [Parameter(ParameterSetName='action_parameters',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=3)]
    [Alias('composite_ids','composite_id','ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/alerts/entities/alerts/v3:patch'
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
          Test-ActionParameter $_ $Valid
        }
        $Param.Format.Body.root = @('composite_ids','action_parameters')
        [void]$Param.Format.Body.Remove('action_parameters')
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
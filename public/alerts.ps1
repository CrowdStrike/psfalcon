function Get-FalconAlert {
<#
.SYNOPSIS
Search for alerts
.DESCRIPTION
Requires 'Alerts: Read'.
.PARAMETER Id
Alert identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IncludeHidden
Include hidden alerts when retrieving results by identifier
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
    [Parameter(ParameterSetName='/alerts/entities/alerts/v2:post',Position=1)]
    [Parameter(ParameterSetName='/alerts/queries/alerts/v2:get',Position=5)]
    [Alias('include_hidden')]
    [boolean]$IncludeHidden,
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
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('composite_ids') }
        Query = @('filter','include_hidden','limit','offset','q','sort')
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
    if ($PSCmdlet.ParameterSetName -eq '/alerts/combined/alerts/v1:post') {
      # Enforce maximum limit for '/alerts/combined/alerts/v1:post'
      if (($PSBoundParameters.Limit -and $PSBoundParameters.Limit -gt 1000) -or
      ($PSBoundParameters.All -and !$PSBoundParameters.Limit)) {
        $PSBoundParameters['Limit'] = 1000
      }
      # Update 'Format'
      $Param.Format = @{ Body = @{ root = @('after','filter','limit','sort') }}
    }
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif ($PSCmdlet.ParameterSetName -eq '/alerts/combined/alerts/v1:post' -and $PSBoundParameters.All) {
      [void]$PSBoundParameters.Remove('All')
      [int]$Count = 0
      do {
        $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters -RawOutput
        if ($Request.errors) {
          # Output errors
          @($Request.errors).foreach{ Write-Error ($_.code,$_.message -join ':') }
        } else {
          # Output resources, update 'after' and increase count
          $Request.resources
          $PSBoundParameters['After'] = $Request.meta.pagination.after
          $Count += $Request.meta.pagination.limit
          if ($Count -lt $Request.meta.pagination.total) {
            # Output running count
            Write-Log $Param.Command ('Retrieved {0} of {1}' -f $Count,$Request.meta.pagination.total)
          }
        }
      } while ($Request.meta.pagination.total -and $Request.meta.pagination.limit -and
        $Request.meta.pagination.after -and $Count -lt $Request.meta.pagination.total)
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
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
      Format = @{
        Body = @{ action_parameters = @('name','value'); root = @('composite_ids')}
        Query = @('include_hidden')
      }
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
        $Param.Format.Body = @{ root = @('composite_ids','action_parameters') }
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
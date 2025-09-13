function Get-FalconQuarantine {
<#
.SYNOPSIS
Search for quarantined files
.DESCRIPTION
Requires 'Quarantined Files: Read'.
.PARAMETER Id
Quarantined file identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Match phrase prefix
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconQuarantine
#>
  [CmdletBinding(DefaultParameterSetName='/quarantine/queries/quarantined-files/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quarantine/entities/quarantined-files/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[A-Fa-f0-9]{64}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get',Position=3)]
    [ValidateSet('hostname.asc','hostname.desc','username.asc','username.desc','date_updated.asc',
      'date_updated.desc','date_created.asc','date_created.desc','paths.path.asc','paths.path.desc',
      'paths.state.asc','paths.state.desc','state.asc','state.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:get')]
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
function Invoke-FalconQuarantineAction {
<#
.SYNOPSIS
Perform actions on quarantined files
.DESCRIPTION
Requires 'Quarantined Files: Write'.
.PARAMETER Action
Action to perform
.PARAMETER Filter
Falcon Query Language statement
.PARAMETER Query
Match phrase prefix
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Quarantined file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconQuarantineAction
#>
  [CmdletBinding(DefaultParameterSetName='/quarantine/entities/quarantined-files/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quarantine/entities/quarantined-files/v1:patch',Mandatory,Position=1)]
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:patch',Mandatory,Position=1)]
    [ValidateSet('release','unrelease','delete',IgnoreCase=$false)]
    [string]$Action,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:patch',Mandatory)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:patch',Position=3)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/quarantine/entities/quarantined-files/v1:patch',Position=2)]
    [Parameter(ParameterSetName='/quarantine/queries/quarantined-files/v1:patch',Position=4)]
    [string]$Comment,
    [Parameter(ParameterSetName='/quarantine/entities/quarantined-files/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[A-Fa-f0-9]{64}$')]
    [Alias('ids')]
    [string[]]$Id
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
function Test-FalconQuarantineAction {
<#
.SYNOPSIS
Check the number of quarantined files potentially affected by a filter-based action
.DESCRIPTION
Requires 'Quarantined Files: Write'.
.PARAMETER Filter
Falcon Query Language statement
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconQuarantineAction
#>
  [CmdletBinding(DefaultParameterSetName='/quarantine/aggregates/action-update-count/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quarantine/aggregates/action-update-count/v1:get',Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
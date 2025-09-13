function Get-FalconReplicatorEvent {
<#
.SYNOPSIS
Search for Falcon Data Replicator events
.DESCRIPTION
Requires 'Falcon Data Replicator: Read'.
.PARAMETER Id
Falcon Data Replicator event identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconReplicatorEvent
#>
  [CmdletBinding(DefaultParameterSetName='/fdr/queries/schema-events/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fdr/entities/schema-events/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get',Position=2)]
    [ValidateSet('name.asc','name.desc','description.asc','description.desc','platform.asc','platform.desc',
      'version.asc','version.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get',Position=3)]
    [int]$Limit,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/fdr/queries/schema-events/v1:get')]
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
function Get-FalconReplicatorField {
<#
.SYNOPSIS
Search for Falcon Data Replicator fields
.DESCRIPTION
Requires 'Falcon Data Replicator: Read'.
.PARAMETER Id
Falcon Data Replicator field identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconReplicatorField
#>
  [CmdletBinding(DefaultParameterSetName='/fdr/queries/schema-fields/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fdr/entities/schema-fields/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get',Position=2)]
    [ValidateSet('name.asc','name.desc','description.asc','description.desc','type.asc','type.desc',
      'universal.asc','universal.desc','values.asc','values.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get',Position=3)]
    [int]$Limit,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/fdr/queries/schema-fields/v1:get')]
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
function Get-FalconReplicatorSchema {
<#
.SYNOPSIS
List all Falcon Data Replicator schema, including fields and events
.DESCRIPTION
Requires 'Falcon Data Replicator: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconReplicatorSchema
#>
  [CmdletBinding(DefaultParameterSetName='/fdr/combined/schema-members/v1:get',SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
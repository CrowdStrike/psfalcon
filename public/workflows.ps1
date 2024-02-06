function Get-FalconWorkflow {
<#
.SYNOPSIS
Search for Falcon Fusion workflows
.DESCRIPTION
Requires 'Workflow: Read'.
.PARAMETER Id
Workflow execution identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Execution
Retrieve information about workflow executions
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconWorkflow
#>
  [CmdletBinding(DefaultParameterSetName='/workflows/combined/definitions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/workflows/entities/execution-results/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','execution_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=1)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=2)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get',Position=3)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Position=3)]
    [int]$Limit,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/workflows/entities/execution-results/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get',Mandatory)]
    [switch]$Execution,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/workflows/combined/definitions/v1:get')]
    [Parameter(ParameterSetName='/workflows/combined/executions/v1:get')]
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
      $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
      Invoke-Falcon @Param -UserInput $PSBoundParameters -Max 500
    }
  }
}
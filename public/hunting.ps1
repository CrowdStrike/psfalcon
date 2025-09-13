function Get-FalconCaoQuery {
<#
.SYNOPSIS
Search intelligence queries that match the provided conditions
.DESCRIPTION
Requires 'CAO Hunting: Read'.
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
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCaoQuery
#>
  [CmdletBinding(DefaultParameterSetName='/hunting/queries/intelligence-queries/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/hunting/entities/intelligence-queries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
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
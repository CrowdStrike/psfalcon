function Get-FalconFileVantageChange {
<#
.SYNOPSIS
Search for Falcon FileVantage changes
.DESCRIPTION
Requires 'Falcon FileVantage: Read'.
.PARAMETER Id
Activity identifier
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
    [Alias('Ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/filevantage/queries/changes/v3:get',Position=2)]
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
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
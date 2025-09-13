function Get-FalconContentState {
<#
.SYNOPSIS
Search for host content file states
.DESCRIPTION
Requires 'Device Content: Read'.
.PARAMETER Id
Host identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContentState
#>
  [CmdletBinding(DefaultParameterSetName='/device-content/queries/states/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/device-content/entities/states/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get',Position=3)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/device-content/queries/states/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 100 }
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

function Get-FalconTailoredEvent {
<#
.SYNOPSIS
Search for tailored intelligence events
.DESCRIPTION
Requires 'Tailored Intelligence: Read'.
.PARAMETER Id
Tailored intelligence event identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconTailoredEvent
#>
  [CmdletBinding(DefaultParameterSetName='/ti/events/queries/events/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ti/events/entities/events/GET/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get',Position=4)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ti/events/queries/events/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 10000 }
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
function Get-FalconTailoredRule {
<#
.SYNOPSIS
Search for tailored intelligence rules
.DESCRIPTION
Requires 'Tailored Intelligence: Read'.
.PARAMETER Id
Tailored intelligence rule identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconTailoredRule
#>
  [CmdletBinding(DefaultParameterSetName='/ti/rules/queries/rules/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ti/rules/entities/rules/GET/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get',Position=4)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/ti/rules/queries/rules/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 10000 }
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
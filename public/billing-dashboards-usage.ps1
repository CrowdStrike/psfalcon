function Get-FalconHostAverage {
<#
.SYNOPSIS
List Falcon weekly average host count
.DESCRIPTION
Requires 'Sensor Usage: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHostAverage
#>
  [CmdletBinding(DefaultParameterSetName='/billing-dashboards-usage/aggregates/weekly-average/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/billing-dashboards-usage/aggregates/weekly-average/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
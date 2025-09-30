function Get-FalconHostAverage {
<#
.SYNOPSIS
List weekly or hourly average Falcon host count for the previous 28 days
.DESCRIPTION
Requires 'Sensor Usage: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Hourly
Return hourly averages instead of weekly
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHostAverage
#>
  [CmdletBinding(DefaultParameterSetName='/billing-dashboards-usage/aggregates/weekly-average/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/billing-dashboards-usage/aggregates/weekly-average/v1:get',Position=1)]
    [Parameter(ParameterSetName='/billing-dashboards-usage/aggregates/hourly-average/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/billing-dashboards-usage/aggregates/hourly-average/v1:get',Mandatory)]
    [switch]$Hourly

  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
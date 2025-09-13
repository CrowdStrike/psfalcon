function Get-FalconWorkflowIntegration {
<#
.SYNOPSIS
Search for Falcon Fusion workflow integrations
.DESCRIPTION
Requires 'API integrations: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconWorkflowIntegration
#>
  [CmdletBinding(DefaultParameterSetName='/plugins/combined/configs/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/plugins/combined/configs/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/plugins/combined/configs/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/plugins/combined/configs/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/plugins/combined/configs/v1:get')]
    [int32]$Offset
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
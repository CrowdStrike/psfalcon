function Get-FalconOverWatchEvent {
<#
.SYNOPSIS
Retrieve the total number of Falcon OverWatch events across all customers
.DESCRIPTION
Requires 'OverWatch Dashboard: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconOverWatchEvent
#>
  [CmdletBinding(DefaultParameterSetName='/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/overwatch-dashboards/aggregates/ow-events-global-counts/v1:get',
       Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconOverWatchDetection {
<#
.SYNOPSIS
Retrieve the total number of Falcon OverWatch detections across all customers
.DESCRIPTION
Requires 'OverWatch Dashboard: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconOverWatchDetection
#>
  [CmdletBinding(DefaultParameterSetName='/overwatch-dashboards/aggregates/detections-global-counts/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/overwatch-dashboards/aggregates/detections-global-counts/v1:get',
       Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconOverWatchIncident {
<#
.SYNOPSIS
Retrieve the total number of Falcon OverWatch incidents across all customers
.DESCRIPTION
Requires 'OverWatch Dashboard: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconOverWatchIncident
#>
  [CmdletBinding(DefaultParameterSetName='/overwatch-dashboards/aggregates/incidents-global-counts/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/overwatch-dashboards/aggregates/incidents-global-counts/v1:get',
       Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
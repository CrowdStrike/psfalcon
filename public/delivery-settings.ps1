function Get-FalconContentControl {
<#
.SYNOPSIS
List Falcon content file update control settings
.DESCRIPTION
Requires 'Channel File Control Settings: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContentControl
#>
  [CmdletBinding(DefaultParameterSetName='/delivery-settings/entities/delivery-settings/v1:get',
    SupportsShouldProcess)]
  [Alias('Get-FalconChannelControl')]
  param()
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Set-FalconContentControl {
<#
.SYNOPSIS
Configure Falcon content file update control settings
.DESCRIPTION
Requires 'Channel File Control Settings: Write'.
.PARAMETER Type
Channel file type
.PARAMETER Cadence
Channel file delivery cadence
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconContentControl
#>
  [CmdletBinding(DefaultParameterSetName='/delivery-settings/entities/delivery-settings/v1:post',
    SupportsShouldProcess)]
  [Alias('Set-FalconChannelControl')]
  param(
    [Parameter(ParameterSetName='/delivery-settings/entities/delivery-settings/v1:post',
      ValueFromPipelineByPropertyName,Mandatory,Position=1)]
    [ValidateSet('sensor_operations','rapid_response_content',IgnoreCase=$false)]
    [Alias('delivery_type')]
    [string]$Type,
    [Parameter(ParameterSetName='/delivery-settings/entities/delivery-settings/v1:post',
      ValueFromPipelineByPropertyName,Mandatory,Position=2)]
    [ValidateSet('early_access','general_availability','pause',IgnoreCase=$false)]
    [Alias('delivery_cadence')]
    [string]$Cadence
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
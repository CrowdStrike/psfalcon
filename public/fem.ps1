function Edit-FalconAsset {
<#
.SYNOPSIS
Assign criticality to an external asset within Falcon Discover
.DESCRIPTION
Requires 'Falcon Discover: Write'.
.PARAMETER Criticality
Asset criticality level
.PARAMETER Comment
Audit log comment
.PARAMETER Cid
Customer identifier
.PARAMETER Id
External asset identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconAsset
#>
  [CmdletBinding(DefaultParameterSetName='/fem/entities/external-assets/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Position=1)]
    [ValidateSet('Critical','High','Noncritical','Unassigned',IgnoreCase=$false)]
    [string]$Criticality,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Position=2)]
    [Alias('criticality_description')]
    [string]$Comment,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/fem/entities/external-assets/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=4)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
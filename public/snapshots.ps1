function Get-FalconSnapshot {
<#
.SYNOPSIS
Search for Falcon Cloud Security snapshots
.DESCRIPTION
Requires 'Snapshot: Read'.
.PARAMETER Id
Falcon Cloud Security snapshot identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSnapshot
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/combined/deployments/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=2)]
    [ValidateSet('account_id.asc','account_id.desc','asset_identifier.asc','asset_identifier.desc',
      'cloud_provider.asc','cloud_provider.desc','instance_type.asc','instance_type.desc',
      'last_updated_timestamp.asc','last_updated_timestamp.desc','region.asc','region.desc','status.asc',
      'status.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/snapshots/combined/deployments/v1:get')]
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
function Get-FalconSnapshotScan {
<#
.SYNOPSIS
Retrieve Falcon Cloud Security snapshot scan reports
.DESCRIPTION
Requires 'Snapshot: Read'.
.PARAMETER Id
Asset identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSnapshotScan
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/scanreports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/scanreports/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids','asset_identifier')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconSnapshotScan {
<#
.SYNOPSIS
Initiate a Falcon Cloud Security snapshot scan
.DESCRIPTION
Requires 'Snapshot: Write'.
.PARAMETER CloudProvider
Cloud provider
.PARAMETER Region
Cloud region
.PARAMETER AccountId
Account identifier
.PARAMETER Id
Asset identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconSnapshotScan
#>
  [CmdletBinding(DefaultParameterSetName='/snapshots/entities/deployments/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('cloud_provider')]
    [string]$CloudProvider,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Region,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('account_id')]
    [string]$AccountId,
    [Parameter(ParameterSetName='/snapshots/entities/deployments/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('asset_identifier')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
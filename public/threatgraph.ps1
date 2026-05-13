function Get-FalconThreatGraphEdge {
<#
.SYNOPSIS
Use the Falcon ThreatGraph to retrieve a list of available edge types or edges related to a vertex
.DESCRIPTION
Requires 'Threatgraph: Read'.
.PARAMETER Id
Vertex identifier
.PARAMETER EdgeType
Edge type
.PARAMETER Scope
Scope of the request
.PARAMETER Direction
Edge direction
.PARAMETER Nano
Return nano-precision entity timestamps
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconThreatGraphEdge
#>
  [CmdletBinding(DefaultParameterSetName='/threatgraph/queries/edge-types/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [Alias('edge_type')]
    [string]$EdgeType,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('cspm','customer','cwpp','device','global',IgnoreCase=$false)]
    [string]$Scope,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',Position=4)]
    [string]$Direction,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',Position=5)]
    [boolean]$Nano,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get',Position=6)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/threatgraph/combined/edges/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('direction','edge_type','ids','limit','nano','offset','scope') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconThreatGraphIndicator {
<#
.SYNOPSIS
Search the Falcon ThreatGraph for indicators seen by hosts
.DESCRIPTION
Requires 'Threatgraph: Read'.
.PARAMETER Type
Indicator type
.PARAMETER Value
Indicator value
.PARAMETER Nano
Return nano-precision entity timestamps
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconThreatGraphIndicator
#>
  [CmdletBinding(DefaultParameterSetName='/threatgraph/combined/ran-on/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get',Mandatory,Position=1)]
    [ValidateSet('domain','ipv4','ipv6','md5','sha1','sha256',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get',Mandatory,Position=2)]
    [string]$Value,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get',Position=3)]
    [boolean]$Nano,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get',Position=4)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/threatgraph/combined/ran-on/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('limit','nano','offset','type','value') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconThreatGraphVertex {
<#
.SYNOPSIS
Retrieve detail about vertexes in the Falcon ThreatGraph
.DESCRIPTION
Requires 'Threatgraph: Read'.
.PARAMETER Id
Vertex identifier
.PARAMETER VertexType
Vertex type [default: 'any-vertex']
.PARAMETER Scope
Scope of the request
.PARAMETER Nano
Return nano-precision entity timestamps
.PARAMETER IncludeEdge
Include a brief list of connected edges
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconThreatGraphVertex
#>
  [CmdletBinding(DefaultParameterSetName='/threatgraph/entities/{vertex-type}/v2:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/threatgraph/combined/{vertex-type}/summary/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Parameter(ParameterSetName='/threatgraph/entities/{vertex-type}/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/threatgraph/combined/{vertex-type}/summary/v1:get',
      ValueFromPipelineByPropertyName,Position=2)]
    [Parameter(ParameterSetName='/threatgraph/entities/{vertex-type}/v2:get',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateSet('accessories','accessory','actor','ad-computers','ad-groups','ad_computer','ad_group',
      'adfs-applications','adfs_application','aggregate-indicators','aggregate_indicator','any-vertex',
      'azure-ad-users','azure-applications','azure_ad_user','azure_application','certificate','certificates',
      'command-lines','command_line','containerized-apps','containerized_app','control-graphs','control_graph',
      'customer','customers','detection','detection-indices','detection_index','detections','devices','direct',
      'directs','domain','domains','extracted-files','extracted_file','firewall','firewall_rule_match',
      'firewall_rule_matches','firewalls','firmware','firmwares','host-names','host_name','hunting-leads',
      'hunting_lead','idp-indicators','idp-sessions','idp_indicator','idp_session','incident','incidents',
      'indicator','indicators','ipv4','ipv6','k8s_cluster','k8s_clusters','kerberos-tickets','kerberos_ticket',
      'legacy-detections','legacy_detection','macro_script','macro_scripts','mobile-apps','mobile-fs-volumes',
      'mobile-indicators','mobile_app','mobile_fs_volume','mobile_indicator','mobile_os_forensics_report',
      'mobile_os_forensics_reports','module','modules','okta-applications','okta-users','okta_application',
      'okta_user','ping-fed-applications','ping_fed_application','process','processes','quarantined-files',
      'quarantined_file','script','scripts','sensor','sensor-self-diagnostics','sensor_self_diagnostic','tag',
      'tags','user-sessions','user_id','user_session','users','wifi-access-points','wifi_access_point','xdr',
      IgnoreCase=$false)]
    [Alias('vertex-type')]
    [string]$VertexType,
    [Parameter(ParameterSetName='/threatgraph/combined/{vertex-type}/summary/v1:get',
      ValueFromPipelineByPropertyName,Position=3)]
    [Parameter(ParameterSetName='/threatgraph/entities/{vertex-type}/v2:get',
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidateSet('cspm','customer','cwpp','device','global',IgnoreCase=$false)]
    [string]$Scope,
    [Parameter(ParameterSetName='/threatgraph/combined/{vertex-type}/summary/v1:get',Position=4)]
    [Parameter(ParameterSetName='/threatgraph/entities/{vertex-type}/v2:get',Position=4)]
    [boolean]$Nano,
    [Parameter(ParameterSetName='/threatgraph/combined/{vertex-type}/summary/v1:get',Mandatory)]
    [switch]$IncludeEdge
  )
  begin {
    if (!$PSBoundParameters.VertexType) { $PSBoundParameters['VertexType'] = 'any-vertex' }
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName -replace '{vertex-type}',$PSBoundParameters.VertexType
      Format = @{ Query = @('ids','nano','scope','vertex-type') }
      Max = 100
    }
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
Register-ArgumentCompleter -CommandName Get-FalconThreatGraphEdge -ParameterName Edge -ScriptBlock {
  Get-FalconThreatGraphEdge -EA 0}
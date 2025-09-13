function Get-FalconCcid {
<#
.SYNOPSIS
Retrieve your Falcon Customer Checksum Identifier (CCID)
.DESCRIPTION
Returns your Customer Checksum Identifier which is requested during the installation of the Falcon Sensor.

Requires 'Sensor Download: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCcid
#>
  [CmdletBinding(DefaultParameterSetName='/sensors/queries/installers/ccid/v1:get',SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function Get-FalconInstaller {
<#
.SYNOPSIS
Search for Falcon sensor installers
.DESCRIPTION
Requires 'Sensor Download: Read'.
.PARAMETER Id
Sha256 hash value
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconInstaller
#>
  [CmdletBinding(DefaultParameterSetName='/sensors/queries/installers/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/sensors/entities/installers/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get',Position=1)]
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get',Position=2)]
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get',Position=3)]
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get')]
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get')]
    [Parameter(ParameterSetName='/sensors/combined/installers/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/sensors/queries/installers/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
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
function Get-FalconStream {
<#
.SYNOPSIS
Retrieve event streams
.DESCRIPTION
Requires 'Event streams: Read'.
.PARAMETER AppId
Connection label
.PARAMETER Format
Format for streaming events [default: json]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconStream
#>
  [CmdletBinding(DefaultParameterSetName='/sensors/entities/datafeed/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/sensors/entities/datafeed/v2:get',Mandatory,Position=1)]
    [string]$AppId,
    [Parameter(ParameterSetName='/sensors/entities/datafeed/v2:get',Position=2)]
    [ValidateSet('json','flatjson',IgnoreCase=$false)]
    [string]$Format
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Receive-FalconInstaller {
<#
.SYNOPSIS
Download a Falcon sensor installer
.DESCRIPTION
Requires 'Sensor Download: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Sha256 hash value
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconInstaller
#>
  [CmdletBinding(DefaultParameterSetName='/sensors/entities/download-installer/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/sensors/entities/download-installer/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('name')]
    [string]$Path,
    [Parameter(ParameterSetName='/sensors/entities/download-installer/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('sha256')]
    [string]$Id,
    [Parameter(ParameterSetName='/sensors/entities/download-installer/v2:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Update-FalconStream {
<#
.SYNOPSIS
Refresh an active event stream
.DESCRIPTION
Requires 'Event streams: Read'.
.PARAMETER AppId
Connection label
.PARAMETER Partition
Partition number
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Update-FalconStream
#>
  [CmdletBinding(DefaultParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post',Mandatory,
      Position=1)]
    [ValidatePattern('^\w{1,32}$')]
    [string]$AppId,
    [Parameter(ParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post',Mandatory,
       Position=2)]
    [int32]$Partition
  )
  process {
    $Endpoint = $PSCmdlet.ParameterSetName -replace '{partition}',$PSBoundParameters.Partition
    [void]$PSBoundParameters.Remove('Partition')
    $PSBoundParameters['action_name'] = 'refresh_active_stream_session'
    Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $Endpoint -UserInput $PSBoundParameters
  }
}
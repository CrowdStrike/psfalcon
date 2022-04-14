function Get-FalconStream {
<#
.SYNOPSIS
Retrieve event streams
.DESCRIPTION
Requires 'Events Streams: Read'.
.PARAMETER AppId
Connection label
.PARAMETER Format
Format for streaming events [default: json]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Event-Streams
#>
    [CmdletBinding(DefaultParameterSetName='/sensors/entities/datafeed/v2:get')]
    param(
        [Parameter(ParameterSetName='/sensors/entities/datafeed/v2:get',Mandatory,Position=1)]
        [string]$AppId,
        [Parameter(ParameterSetName='/sensors/entities/datafeed/v2:get',Position=2)]
        [ValidateSet('json','flatjson',IgnoreCase=$false)]
        [string]$Format
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('format','appId') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Update-FalconStream {
<#
.SYNOPSIS
Refresh an active event stream
.DESCRIPTION
Requires 'Events Streams: Read'.
.PARAMETER AppId
Connection label
.PARAMETER Partition
Partition number
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Event-Streams
#>
    [CmdletBinding(DefaultParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post')]
    param(
        [Parameter(ParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post',Mandatory,
            Position=1)]
        [ValidatePattern('^\w{1,32}$')]
        [string]$AppId,
        [Parameter(ParameterSetName='/sensors/entities/datafeed-actions/v1/{partition}:post',Mandatory,
           Position=2)]
        [int32]$Partition
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $Endpoint
            Format = @{ Query = @('action_name','appId') }
        }
    }
    process {
        $Endpoint = $PSCmdlet.ParameterSetName -replace '{partition}',$PSBoundParameters.Partition
        [void]$PSBoundParameters.Remove('Partition')
        $PSBoundParameters['action_name'] = 'refresh_active_stream_session'
        Invoke-Falcon @Param -Endpoint $Endpoint -Inputs $PSBoundParameters
    }
}
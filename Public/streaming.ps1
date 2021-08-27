function Get-FalconStream {
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/datafeed/v2:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/datafeed/v2:get', Mandatory = $true, Position = 1)]
        [string] $AppId,

        [Parameter(ParameterSetName = '/sensors/entities/datafeed/v2:get', Position = 2)]
        [ValidateSet('json', 'flatjson')]
        [string] $Format
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('format', 'appId')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Update-FalconStream {
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/datafeed-actions/v1/{partition}:post')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/datafeed-actions/v1/{partition}:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{1,32}$')]
        [string] $AppId,

        [Parameter(ParameterSetName = '/sensors/entities/datafeed-actions/v1/{partition}:post', Mandatory = $true,
            Position = 2)]
        [int] $Partition
    )
    begin {
        $Endpoint = $PSCmdlet.ParameterSetName -replace '{partition}', $PSBoundParameters.Partition
        [void] $PSBoundParameters.Remove('Partition')
        $PSBoundParameters['action_name'] = 'refresh_active_stream_session'
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $Endpoint
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('action_name', 'appId')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
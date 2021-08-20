function Get-FalconIocHost {
    [CmdletBinding(DefaultParameterSetName = '/indicators/queries/devices/v1:get')]
    param(
        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/indicators/aggregates/devices-count/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Mandatory = $true, Position = 2)]
        [Parameter(ParameterSetName = '/indicators/aggregates/devices-count/v1:get', Mandatory = $true,
            Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Position = 3)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Position = 4)]
        [ValidateRange(1,100)]
        [string] $Limit,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/indicators/aggregates/devices-count/v1:get', Mandatory = $true)]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('type', 'offset', 'limit', 'value')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIocProcess {
    [CmdletBinding(DefaultParameterSetName = '/indicators/queries/processes/v1:get')]
    param(
        [Parameter(ParameterSetName = '/processes/entities/processes/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^pid:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Mandatory = $true, Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Mandatory = $true, Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [string] $HostId,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Position = 5)]
        [ValidateRange(1,100)]
        [string] $Limit,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get')]
        [switch] $All
    )
    begin {
        $Fields = @{
            HostId = 'device_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'device_id', 'offset', 'type', 'value', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
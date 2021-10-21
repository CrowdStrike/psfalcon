function Get-FalconCcid {
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/ccid/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function Get-FalconInstaller {
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/v1:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/installers/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Position = 1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get')]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
        Invoke-Falcon @Param
    }
}
function Receive-FalconInstaller {
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/download-installer/v1:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/download-installer/v1:get', Mandatory = $true,
            ValueFromPipeline = $true, Position = 1)]
        [Alias('sha256')]
        [ValidatePattern('^\w{64}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/sensors/entities/download-installer/v1:get', Mandatory = $true,
            Position = 2)]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Query = @('id')
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
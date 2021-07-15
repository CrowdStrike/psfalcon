function Get-FalconCcid {
<#
.Synopsis
Retrieve your customer checksum identifier (CCID)
.Role
sensor-installers:read
#>
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/ccid/v1:get')]
    param()
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconInstaller {
<#
.Synopsis
Search for Falcon sensor installers
.Parameter Ids
One or more sensor installer identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
sensor-installers:read
#>
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/v1:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/installers/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{64}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/sensors/queries/installers/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/sensors/combined/installers/v1:get', Position = 1)]
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
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconInstaller {
<#
.Synopsis
Download sensor installer by Sha256 ID
.Parameter Id
Sensor installer identifier
.Parameter Path
Destination path
.Role
sensor-installers:read
#>
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/download-installer/v1:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/download-installer/v1:get', Mandatory = $true,
            Position = 1)]
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
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/octet-stream'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('id')
                Outfile = 'path'
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
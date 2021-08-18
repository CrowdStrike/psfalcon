function Get-FalconCcid {
<#
.Synopsis
Retrieve your Customer Checksum Identifier (CCID)
.Description
Requires 'sensor-installers:read'.

Returns your Customer Checksum Identifier, which is requested during the installation of the Falcon Sensor.
.Role
sensor-installers:read
.Example
PS>Get-FalconCcid
#>
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/ccid/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}
function Get-FalconInstaller {
<#
.Synopsis
Search for Falcon Sensor installers
.Description
Requires 'sensor-installers:read'.
.Parameter Ids
Sensor installer Sha256 hash value(s)
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
.Example
PS>Get-FalconInstaller -Filter "platform:'linux'" -Detailed -All

Return detailed information about all available Falcon Sensor installers for Linux.
.Example
PS>Get-FalconInstaller -Ids <id>, <id>

Retrieve detailed information about Falcon Sensor installers <id> and <id>.
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
Download a Falcon Sensor installer
.Description
Requires 'sensor-installers:read'.
.Parameter Id
Sensor installer Sha256 hash value
.Parameter Path
Destination path
.Role
sensor-installers:read
.Example
PS>Receive-FalconInstaller -Id <sha256> -Path .\WindowsSensor.exe

Download the 'WindowsSensor.exe' package matching <sha256> to your local directory.
.Example
PS>Get-FalconInstaller -Filter "os:'Amazon Linux'" -Sort release_date -Limit 1 -Detailed | ForEach-Object {
    Receive-FalconInstaller -Id $_.sha256 -Path $_.name }

Find and download the most recent Falcon Sensor installer package for 'Amazon Linux' to your local directory.
#>
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/download-installer/v1:get')]
    param(
        [Parameter(ParameterSetName = '/sensors/entities/download-installer/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
                Accept = 'application/octet-stream'
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
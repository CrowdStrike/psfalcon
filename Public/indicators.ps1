function Get-FalconIOCHost {
<#
.Synopsis
List hosts that have observed a custom indicator
.Parameter Type
Custom indicator type
.Parameter Value
Custom indicator value
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter All
Repeat requests until all available results are retrieved
.Role
iocs:read
#>
    [CmdletBinding(DefaultParameterSetName = '/indicators/queries/devices/v1:get')]
    param(
        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Mandatory = $true, Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Position = 3)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get', Position = 4)]
        [ValidateRange(1,100)]
        [string] $Limit,

        [Parameter(ParameterSetName = '/indicators/queries/devices/v1:get')]
        [switch] $All
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('type', 'offset', 'limit', 'value')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIOCProcess {
<#
.Synopsis
Search for process identifiers on a specific host involving a custom indicator
.Parameter Ids
One or more process identifiers
.Parameter Type
Custom indicator type
.Parameter Value
Custom indicator value
.Parameter HostId
Host identifier
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Role
iocs:read
#>
    [CmdletBinding(DefaultParameterSetName = '/indicators/queries/processes/v1:get')]
    param(
        [Parameter(ParameterSetName = '/processes/entities/processes/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^pid:\w{32}:\d{1,}$')]
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
        [string] $Offset,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get', Position = 5)]
        [ValidateRange(1,100)]
        [string] $Limit,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/indicators/queries/processes/v1:get')]
        [switch] $All
    )
    begin {
        $PSBoundParameters.Add('device_id', $PSBoundParameters.HostId)
        [void] $PSBoundParameters.Remove('HostId')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids', 'device_id', 'offset', 'type', 'value', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIOCTotal {
<#
.Synopsis
Provide a count of the total hosts that have observed a custom indicator
.Parameter Type
Custom indicator type
.Parameter Value
Custom indicator value
.Role
iocs:read
#>
    [CmdletBinding(DefaultParameterSetName = '/indicators/aggregates/devices-count/v1:get')]
    param(
        [Parameter(ParameterSetName = '/indicators/aggregates/devices-count/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidateSet('domain', 'ipv4', 'ipv6', 'md5', 'sha256')]
        [string] $Type,

        [Parameter(ParameterSetName = '/indicators/aggregates/devices-count/v1:get', Mandatory = $true,
            Position = 2)]
        [string] $Value
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('type', 'value')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
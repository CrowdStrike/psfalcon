function Get-FalconIocHost {
<#
.Synopsis
List Host identifiers that have observed a custom indicator
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
        [int] $Offset,

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
<#
.Synopsis
Search for process identifiers involving a custom indicator on a specific Host
.Parameter Ids
Process identifier(s)
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
function Get-FalconIocTotal {
<#
.Synopsis
Provide a count of total Host(s) that have observed a custom indicator
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
            Format   = @{
                Query = @('type', 'value')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconProcess {
<#
.Synopsis
Retrieve process tree information
.Parameter Ids
Process identifier(s)
.Role
iocs:read
#>
    [CmdletBinding(DefaultParameterSetName = '/processes/entities/processes/v1:get')]
    param(
        [Parameter(ParameterSetName = '/processes/entities/processes/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^pid:\w{32}:\d{1,}$')]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIocHost {
<#
.Synopsis
List Host identifiers that have observed a custom indicator
.Description
Requires 'iocs:read'.
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
.Parameter Total
Display the total result count instead of results
.Role
iocs:read
.Example
PS>Get-FalconIocHost -Type domain -Value example.com

List the first set of host identifiers that observed the 'domain' indicator 'example.com'.
.Example
PS>Get-FalconIocHost -Type domain -Value example.com -Total

Display a total count of hosts that observed the 'domain' indicator 'example.com'.
#>
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
<#
.Synopsis
Search for process identifiers involving a custom indicator on a specific Host
.Description
Requires 'iocs:read'.
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
.Example
PS>Get-FalconIocProcess -Type domain -Value example.com -HostId <id>

Retrieve the first set of process identifiers for host <id> that include the event related to the custom 'domain'
indicator 'example.com'.
.Example
PS>Get-FalconIocProcess -Ids <id>, <id>

Retrieve summary information about process identifiers <id> and <id>.
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
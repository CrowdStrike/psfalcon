function Add-FalconHostTag {
<#
.Synopsis
Add FalconGroupingTags to one or more Host(s)
.Description
Requires 'devices:write'.
.Parameter Ids
Host identifier(s)
.Parameter Tags
FalconGroupingTag value(s)
.Role
devices:write
.Example
PS>Add-FalconHostTag -Ids <id>, <id> -Tags 'FalconGroupingTags/Example', 'FalconGroupingTags/Test'

Add 'FalconGroupingTags/Example' and 'FalconGroupingTags/Test' to hosts <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
        $PSBoundParameters.Add('action', 'add')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHost {
<#
.Synopsis
Search for Hosts
.Description
Requires 'devices:read'.
.Parameter Ids
Host identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Hidden
Restrict search to 'hidden' hosts
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
devices:read
.Example
PS>Get-FalconHost -Filter "platform_name:'Windows'" -Detailed -All

Return detailed results for all 'Windows' hosts.
.Example
PS>Get-FalconHost -Filter "hostname:['EXAMPLE-PC']" -Detailed

Return detailed results for the host named 'EXAMPLE-PC' (exact match).
.Example
PS>Get-FalconHost -Ids <id>, <id>

Return detailed results for hosts <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/devices-scroll/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Mandatory = $true)]
        [switch] $Hidden,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'filter', 'sort', 'limit', 'offset')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconHostAction {
<#
.Synopsis
Perform actions on Hosts
.Description
Requires 'devices:write'.
.Parameter Name
Action to perform
.Parameter Ids
Host identifier(s)
.Role
devices:write
.Example
PS>Invoke-FalconHostAction -Name contain -Ids <id>, <id>

Send a network containment request for hosts <id> and <id>.
.Example
PS>Invoke-FalconHostAction -Name hide_host -Ids <id>, <id>

Hide the hosts <id> and <id> from the Falcon console. Hidden hosts can be found using 'Get-FalconHost -Hidden'.
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices-actions/v2:post')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('contain', 'lift_containment', 'hide_host', 'unhide_host')]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Name = 'action_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root = @('ids')
                }
            }
            Max = if ($PSBoundParameters.Name -match '^(hide_host|unhide_host)$') {
                100
            } else {
                500
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconHostTag {
<#
.Synopsis
Remove FalconGroupingTags from one or more hosts
.Description
Requires 'devices:write'.
.Parameter Ids
Host identifier(s)
.Parameter Tags
FalconGroupingTag value(s)
.Role
devices:write
.Example
PS>Remove-FalconHostTag -Ids <id>, <id> -Tags 'FalconGroupingTags/Example', 'FalconGroupingTags/Test'

Remove 'FalconGroupingTags/Example' and 'FalconGroupingTags/Test' from hosts <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
        $PSBoundParameters.Add('action', 'remove')
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
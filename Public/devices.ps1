function Add-FalconHostTag {
<#
.Synopsis
Append Falcon GroupingTags on one or more hosts
.Parameter Ids
One or more Host identifiers
.Parameter Tags
One or more GroupingTag values
.Role
devices:write
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
        if ($PSBoundParameters.Ids) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('device_ids', $PSBoundParameters.Ids)
            $PSBoundParameters.Add('action', 'add')
            [void] $PSBoundParameters.Remove('Ids')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
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
function Edit-FalconHostGroup {
<#
.Synopsis
Update Host Groups by specifying the ID of the group and details to update
.Parameter Id
The id of the group to update
.Parameter Name
The new name of the group
.Parameter Description
The new description of the group
.Parameter AssignmentRule
The new assignment rule of the group. Note: If the group type is static, this field cannot be updated manually
.Role
host-group:write
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:patch', Position = 4)]
        [string] $AssignmentRule
    )
    begin {
        if ($PSBoundParameters.AssignmentRule) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('assignment_rule', $PSBoundParameters.AssignmentRule)
            [void] $PSBoundParameters.Remove('AssignmentRule')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('assignment_rule', 'id', 'name', 'description')
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
Search for hosts
.Parameter Ids
One or more Host identifiers
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
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/devices-scroll/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/v1:get', Position = 1, Mandatory = $true)]
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
        [ValidateScript({ $_ -notmatch '^\d{1,}$' })]
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
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Headers = @{
                Accept = 'application/json'
            }
            Inputs = $PSBoundParameters
            Format = @{
                Query = @('ids', 'filter', 'sort', 'limit', 'offset')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconHostGroup {
<#
.Synopsis
Search for Host Groups in your environment by providing an FQL filter and paging details
.Parameter Ids
One or more Host Group identifiers
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
host-group:read
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'group_type.asc', 'group_type.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get')]
        [int] $Offset,

        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-groups/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/host-groups/v1:get')]
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
function Get-FalconHostGroupMember {
<#
.Synopsis
Search for members of a Host Group in your environment by providing an FQL filter and paging details
.Parameter Id
A Host Group identifier to search for members of
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
The maximum records to return
.Parameter Offset
The offset to start retrieving records from
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
host-group:read
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get')]
        [Parameter(ParameterSetName = '/devices/combined/host-group-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/host-group-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id', 'filter', 'sort', 'limit', 'offset')
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
Take various actions on the hosts in your environment. Contain or lift containment on a host. Delete or
restore a host.
.Parameter Name
Specify one of these actions:

contain: This action contains the host, which stops any network communications to locations other than the
    CrowdStrike cloud and IPs specified in your containment policy

lift_containment: This action lifts containment on the host, which returns its network communications to normal

hide_host: This action will delete a host. After the host is deleted, no new detections for that host will be
    reported via UI or APIs

unhide_host: This action will restore a host. Detection reporting will resume after the host is restored
.Parameter Ids
One or more Host identifiers
.Role
devices:write
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
        if ($PSBoundParameters.Name) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('action_name', $PSBoundParameters.Name)
            [void] $PSBoundParameters.Remove('Name')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root              = @('ids')
                    action_parameters = @('name')
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
function Invoke-FalconHostGroupAction {
<#
.Synopsis
Perform the specified action on the Host Groups specified in the request
.Parameter Name
The action to perform
.Parameter Ids
One or more Host Group identifiers
.Role
host-group:write
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-group-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-group-actions/v1:post', Mandatory = $true)]
        [ValidateSet('add-hosts', 'remove-hosts')]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/host-group-actions/v1:post', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        if ($PSBoundParameters.Name) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('action_name', $PSBoundParameters.Name)
            [void] $PSBoundParameters.Remove('Name')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root              = @('ids')
                    action_parameters = @('value', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconHostGroup {
<#
.Synopsis
Delete a set of Host Groups by specifying their IDs
.Parameter Ids
One or more Host identifiers
.Role
host-group:write
#>
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/host-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/host-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
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
function Remove-FalconHostTag {
<#
.Synopsis
Remove Falcon GroupingTags on one or more hosts
.Parameter Ids
One or more Host identifiers
.Parameter Tags
One or more GroupingTag values
.Role
devices:write
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
        if ($PSBoundParameters.Ids) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('device_ids', $PSBoundParameters.Ids)
            [void] $PSBoundParameters.Remove('Ids')
            $PSBoundParameters.Add('action', 'remove')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept      = 'application/json'
                ContentType = 'application/json'
            }
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
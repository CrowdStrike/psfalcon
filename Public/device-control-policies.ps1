function Edit-FalconDeviceControlPolicy {
<#
.Synopsis
Modify Device Control policies
.Parameter Array
An array of Device Control policies to modify in a single request
.Parameter Id
Device Control policy identifier
.Parameter Name
Device Control policy name
.Parameter Settings
Hashtable of Device Control policy settings
.Parameter Description
Device Control policy description
.Role
device-control-policies:write
.Example
PS>$Settings = @{ enforcement_mode = 'MONITOR_ENFORCE'; classes = @( @{ id = 'MASS_STORAGE'; action = 'BLOCK_ALL';
exceptions = @(@{ combined_id = '1234_5678_000000000000'; action = 'BLOCK_WRITE_EXECUTE' })})}
PS>Edit-FalconDeviceControlPolicy -Id <id> -Settings $Settings

Modify Device Control policy <id> and set 'enforcement_mode' to 'MONITOR_ENFORCE', with the 'MASS_STORAGE'
category configured to 'BLOCK_ALL', including an exception for 'combined_id' '1234_5678_000000000000'.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconDeviceControlPolicy'
                    Endpoint = '/policy/entities/device-control/v1:patch'
                    Required = @('id')
                    Pattern  = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/device-control/v1:patch'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'id', 'description', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicy {
<#
.Synopsis
Search for Device Control policies
.Parameter Ids
Device Control policy identifier(s)
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
device-control-policies:read
.Example
PS>Get-FalconDeviceControlPolicy -Filter "name:!'platform_default'" -Detailed -All

Return detailed information about all Device Control policies not named 'platform_default'.
.Example
PS>Get-FalconDeviceControlPolicy -Ids <id>, <id>

Return detailed information about Device Control policies <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicyMember {
<#
.Synopsis
Search for members of Device Control policies
.Parameter Id
Device Control policy identifier
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
device-control-policies:read
.Example
PS>Get-FalconDeviceControlPolicyMember -Id <id> -All

Return all identifiers for hosts in the Device Control policy <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'id', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconDeviceControlPolicyAction {
<#
.Synopsis
Perform actions on Device Control policies
.Parameter Name
Action to perform
.Parameter Id
Device Control policy identifier
.Parameter GroupId
Host group identifier
.Role
device-control-policies:write
.Example
PS>Invoke-FalconDeviceControlPolicyAction -Name add-host-group -Id <policy_id> -GroupId <group_id>

Add the Host Group <group_id> to Device Control policy <policy_id>.
.Example
PS>Invoke-FalconDeviceControlPolicyAction -Name enable -Id <policy_id>

Enable Device Control policy <policy_id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        $Fields = @{
            name = 'action_name'
        }
        $PSBoundParameters.Add('Ids', @( $PSBoundParameters.Id ))
        [void] $PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $PSBoundParameters.Add('action_parameters', @(
                @{
                    name  = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            ))
            [void] $PSBoundParameters.Remove('GroupId')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root = @('ids', 'action_parameters')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconDeviceControlPolicy {
<#
.Synopsis
Create Device Control policies
.Parameter Array
An array of Device Control policies to create in a single request
.Parameter PlatformName
Operating System platform
.Parameter Name
Device Control policy name
.Parameter Settings
Hashtable of Device Control policy settings
.Parameter CloneId
Clone an existing Device Control policy
.Role
device-control-policies:write
.Example
PS>$Settings = @{ enforcement_mode = 'MONITOR_ENFORCE'; classes = @( @{ id = 'MASS_STORAGE'; action = 'BLOCK_ALL';
    exceptions = @(@{ combined_id = '1234_5678_000000000000'; action = 'BLOCK_WRITE_EXECUTE' })})}
PS>New-FalconDeviceControlPolicy -PlatformName Windows -Name Example -Settings $Settings

Create Device Control policy 'Example' for Windows hosts, with an 'enforcement_mode' of 'MONITOR_ENFORCE', and the
'MASS_STORAGE' category configured to 'BLOCK_ALL', including an exception for 'combined_id'
'1234_5678_000000000000'.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconDeviceControlPolicy'
                    Endpoint = '/policy/entities/device-control/v1:post'
                    Required = @('name', 'platform_name')
                    Content  = @('platform_name')
                    Format   = @{
                        platform_name = 'PlatformName'
                    }
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Position = 3)]
        [object] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [string] $CloneId
    )
    begin {
        $Fields = @{
            Array        = 'resources'
            CloneId      = 'clone_id'
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/device-control/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'description', 'clone_id', 'platform_name', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconDeviceControlPolicy {
<#
.Synopsis
Remove Device Control policies
.Parameter Ids
Device Control policy identifier(s)
.Role
device-control-policies:write
.Example
PS>Remove-FalconDeviceControlPolicy -Ids <id>, <id>

Delete Device Control policies <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:delete', Mandatory = $true,
            Position = 1)]
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
function Set-FalconDeviceControlPrecedence {
<#
.Synopsis
Set Device Control policy precedence
.Description
All Device Control policy identifiers must be supplied in order (with the exception of the 'platform_default'
policy) to define policy precedence.
.Parameter PlatformName
Operating System platform
.Parameter Ids
All Device Control policy identifiers in desired precedence order
.Role
device-control-policies:write
.Example
PS>Set-FalconDeviceControlPrecedence -PlatformName Windows -Ids <id_1>, <id_2>, <id_3>

Set the Device Control policy precedence for 'Windows' policies in order <id_1>, <id_2>, <id_3>. All policy
identifiers must be supplied.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('platform_name', 'ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconPreventionPolicy {
<#
.Synopsis
Modify Prevention policies
.Parameter Array
An array of Prevention policies to modify in a single request
.Parameter Id
Prevention policy identifier
.Parameter Name
Prevention policy name
.Parameter Settings
An array of Prevention policy settings
.Parameter Description
Prevention policy description
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/prevention/v1:patch'
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
function Get-FalconPreventionPolicy {
<#
.Synopsis
Search for Prevention policies
.Parameter Ids
Prevention policy identifier(s)
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
prevention-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/prevention/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get')]
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
function Get-FalconPreventionPolicyMember {
<#
.Synopsis
Search for members of Prevention policies
.Parameter Id
Prevention policy identifier
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
prevention-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/prevention-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get')]
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
function Invoke-FalconPreventionPolicyAction {
<#
.Synopsis
Perform actions on Prevention policies
.Parameter Name
Action to perform
.Parameter Id
Prevention policy identifier
.Parameter GroupId
Host group identifier
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/prevention-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'add-rule-group', 'disable', 'enable', 'remove-host-group',
            'remove-rule-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/prevention-actions/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/prevention-actions/v1:post', Position = 3)]
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
            $Action = @{
                name  = 'group_id'
                value = @( $PSBoundParameters.GroupId )
            }
            $PSBoundParameters.Add('action_parameters', $Action)
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
function New-FalconPreventionPolicy {
<#
.Synopsis
Create Prevention policies
.Parameter Array
An array of Prevention policies to create in a single request
.Parameter PlatformName
Operating System platform
.Parameter Name
Prevention policy name
.Parameter Settings
An array of Prevention policy settings
.Parameter Description
Sensor Update policy description
.Parameter CloneId
Clone an existing Prevention policy
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v2:post', Mandatory = $true, Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v2:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v2:post', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v2:post', Position = 4)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:post', Position = 5)]
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
            Endpoint = '/policy/entities/prevention/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('description', 'clone_id', 'platform_name', 'name', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconPreventionPolicy {
<#
.Synopsis
Delete Prevention policies
.Parameter Ids
Prevention policy identifier(s)
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:delete', Mandatory = $true, Position = 1)]
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
function Set-FalconPreventionPrecedence {
<#
.Synopsis
Set Prevention policy precedence
.Parameter PlatformName
Operating System platform
.Parameter Ids
All Prevention policy identifiers in desired precedence order
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/prevention-precedence/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/prevention-precedence/v1:post', Mandatory = $true,
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
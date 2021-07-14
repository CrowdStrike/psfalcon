function Edit-FalconFirewallPolicy {
<#
.Synopsis
Modify Firewall Management policies
.Parameter Array
An array of Firewall Management policies to modify in a single request
.Parameter Id
Firewall Management policy identifier
.Parameter Name
Firewall Management policy name
.Parameter Description
Firewall Management policy description
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Position = 3)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'id', 'description')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallPolicy {
<#
.Synopsis
Search for Firewall Management policies
.Parameter Ids
One or more Firewall Management policy identifiers
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
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/firewall/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get')]
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
function Get-FalconFirewallPolicyMember {
<#
.Synopsis
Search for members of Firewall Management policies
.Parameter Id
Firewall Management policy identifier
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
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/firewall-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get')]
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
function Invoke-FalconFirewallPolicyAction {
<#
.Synopsis
Perform the specified action on the Firewall Policies specified in the request
.Parameter Ids
One or more XXX identifiers
.Parameter ActionName

.Parameter Name

.Parameter Value

.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $ActionName,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true)]
        [string] $Value
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body = @{
                    root = @('ids')
                    action_parameters = @('name', 'value')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconFirewallPolicy {
<#
.Synopsis
Create Firewall Policies by specifying details about the policy to create
.Parameter Description

.Parameter CloneId

.Parameter PlatformName

.Parameter Name

.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post')]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post')]
        [string] $CloneId,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Mandatory = $true)]
        [string] $Name
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('description', 'clone_id', 'platform_name', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconFirewallPolicy {
<#
.Synopsis
Delete a set of Firewall Policies by specifying their IDs
.Parameter Ids
One or more XXX identifiers
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:delete', Mandatory = $true)]
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
function Set-FalconFirewallPrecedence {
<#
.Synopsis
Sets the precedence of Firewall Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
.Parameter PlatformName

.Parameter Ids
One or more XXX identifiers
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall-precedence/v1:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/firewall-precedence/v1:post', Mandatory = $true)]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
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
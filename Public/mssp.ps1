function Add-FalconCIDGroupMember {
<#
.Synopsis
Add CID Group members
.Parameter Id
CID group identifier
.Parameter CIDs
One or more CIDs
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:post', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $CIDs
    )
    begin {
        $Fields = @{
            Id = 'cid_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('cid_group_id', 'cids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Add-FalconGroupRole {
<#
.Synopsis
Assign role(s) to CID and User Groups
.Parameter CidGroupId
CID group identifier
.Parameter UserGroupId
User Group identifier
.Parameter RoleIds
One or more roles
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/mssp-roles/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $CidGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:post', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $UserGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:post', Mandatory = $true, Position = 3)]
        [array] $RoleIds
    )
    begin {
        $Fields = @{
            CidGroupId  = 'cid_group_id'
            RoleIds     = 'role_ids'
            UserGroupId = 'user_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('cid_group_id', 'user_group_id', 'role_ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Add-FalconUserGroupMember {
<#
.Synopsis
Add User Group members
.Parameter Id
User group identifier
.Parameter UserIds
One or more User identifiers
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-group-members/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $UserIds
    )
    begin {
        $Fields = @{
            Id      = 'user_group_id'
            UserIds = 'user_uuids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('user_uuids', 'user_group_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconCIDGroup {
<#
.Synopsis
Modify CID groups
.Parameter Id
CID group identifier
.Parameter Name
CID group name
.Parameter Description
CID group description
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:patch', Position = 3)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Id = 'cid_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('description', 'cid_group_id', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconUserGroup {
<#
.Synopsis
Update existing User Group(s)
.Parameter Id
User group identifier
.Parameter Name
User group name
.Parameter Description
User group description
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:patch', Position = 3)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Id = 'user_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('description', 'name', 'user_group_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCIDGroup {
<#
.Synopsis
Search for CID groups
.Parameter Ids
One or more CID group identifiers
.Parameter Name
CID group name
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
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/cid-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp', 'name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Ids = 'cid_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cid_group_ids', 'offset', 'limit', 'name', 'sort')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconCIDGroupMember {
<#
.Synopsis
Search for CID group members
.Parameter Ids
One or more CID group identifiers
.Parameter Id
CID group identifier
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
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,
        
        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Id  = 'cid'
            Ids = 'cid_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('cid_group_ids', 'offset', 'limit', 'sort', 'cid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconGroupRole {
<#
.Synopsis
Search for user group roles
.Parameter Ids
One or more combined group identifiers [<cid_group_id>:<user_group_id>]
.Parameter CidGroupId
CID group identifier
.Parameter UserGroupId
User group identifier
.Parameter RoleId
Role group identifier
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
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/mssp-roles/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}:\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $CidGroupId,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $UserGroupId,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 3)]
        [string] $RoleId,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 4)]
        [ValidateSet('last_modified_timestamp')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 5)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get', Position = 6)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/mssp-roles/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            CidGroupId  = 'cid_group_id'
            RoleId      = 'role_id'
            UserGroupId = 'user_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'role_id', 'cid_group_id', 'sort', 'offset', 'user_group_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconMemberCid {
<#
.Synopsis
Search for child CIDs
.Parameter Ids
One or more child CID identifiers
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Role
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/children/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/children/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get', Position = 1)]
        [ValidateSet('last_modified_timestamp')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get', Position = 2)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserGroup {
<#
.Synopsis
Search for user groups
.Parameter Ids
One or more user group identifiers
.Parameter Name
User group name
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
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/user-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp', 'name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Ids = 'user_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'user_group_ids', 'limit', 'name')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserGroupMember {
<#
.Synopsis
Search for members of a user group, or groups assigned to a user
.Parameter Ids
One or more user group identifiers, to find group members
.Parameter UserUuid
A User identifier, to find group membership
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
mssp:read
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/user-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Ids    = 'user_group_ids'
            UserId = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'user_group_ids', 'limit', 'user_uuid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconCIDGroup {
<#
.Synopsis
Create CID groups
.Parameter Name
CID group name
.Parameter Description
CID group description
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Description
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
                Body = @{
                    resources = @('description', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconUserGroup {
<#
.Synopsis
Create User groups
.Parameter Name
User group name
.Parameter Description
User group description
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Description
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
                Body = @{
                    resources = @('description', 'name')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconCIDGroup {
<#
.Synopsis
Remove CID groups
.Parameter CidGroupIds

.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Ids = 'cid_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('cid_group_ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconCIDGroupMember {
<#
.Synopsis
Remove members from a CID group
.Parameter Id
CID group identifier
.Parameter CIDs
One or more CIDs
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:delete', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $CIDs
    )
    begin {
        $Fields = @{
            Id = 'cid_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('cid_group_id', 'cids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconGroupRole {
<#
.Synopsis
Remove role assignment(s) between User Groups and CID Groups
.Parameter CidGroupId
CID group identifier
.Parameter UserGroupId
User group identifier
.Parameter RoleIds
One or more roles (leave blank to remove User Group from CID Group)
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/mssp-roles/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $CidGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $UserGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Mandatory = $true, Position = 3)]
        [array] $RoleIds
    )
    begin {
        $Fields = @{
            CidGroupId  = 'cid_group_id'
            UserGroupId = 'user_group_id'
            RoleIds     = 'role_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    resources = @('cid_group_id', 'user_group_id', 'role_ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconUserGroup {
<#
.Synopsis
Remove User groups
.Parameter Ids
One or more user group identifiers
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Ids = 'user_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('user_group_ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconUserGroupMember {
<#
.Synopsis
Remove members from a User group
.Parameter Id
User group identifier
.Parameter UserIds
One or more user identifiers
.Role
mssp:write
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-group-members/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:delete', Mandatory = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:delete', Mandatory = $true)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $UserIds
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
                Body = @{
                    resources = @('user_uuids', 'user_group_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
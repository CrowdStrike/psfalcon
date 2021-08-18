function Add-FalconCidGroupMember {
<#
.Synopsis
Add CID group members
.Description
Requires 'mssp:write'.
.Parameter Id
CID group identifier
.Parameter CIDs
CID(s)
.Role
mssp:write
.Example
PS>Add-FalconCidGroupMember -Id <id> -CIDs <cid>, <cid>

Add CIDs <cid> and <cid> to CID group <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
Assign role(s) between a CID and user group
.Description
Requires 'mssp:write'.
.Parameter CidGroupId
CID group identifier
.Parameter UserGroupId
User Group identifier
.Parameter RoleIds
Role(s)
.Role
mssp:write
.Example
PS>Add-FalconGroupRole -CidGroupId <cid_group_id> -UserGroupId <user_group_id> -RoleIds <role_id>, <role_id>

Assign roles <role_id> and <role_id> between CID group <cid_group_id> and user group <user_group_id>.
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
Add user group members
.Description
Requires 'mssp:write'.
.Parameter Id
User group identifier
.Parameter UserIds
User identifier(s)
.Role
mssp:write
.Example
PS>Add-FalconUserGroupMember -Id <id> -UserIds <uuid>, <uuid>

Add users <uuid> and <uuid> to user group <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-group-members/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
function Edit-FalconCidGroup {
<#
.Synopsis
Modify a CID group
.Description
Requires 'mssp:write'.
.Parameter Id
CID group identifier
.Parameter Name
CID group name
.Parameter Description
CID group description
.Role
mssp:write
.Example
PS>Edit-FalconCidGroup -Id <id> -Name 'Updated Name' -Description 'Updated name for manual testing'

Change the name of CID group <id> to 'Updated Name'.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
Modify a user group
.Description
Requires 'mssp:write'.
.Parameter Id
User group identifier
.Parameter Name
User group name
.Parameter Description
User group description
.Role
mssp:write
.Example
PS>Edit-FalconUserGroup -Id <id> -Name 'Updated Name' -Description 'Updated name for manual testing'

Change the name of user group <id> to 'Updated Name'.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
function Get-FalconCidGroup {
<#
.Synopsis
Search for CID groups
.Description
Requires 'mssp:read'.
.Parameter Ids
CID group identifier(s)
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
.Example
PS>Get-FalconCidGroup

Return the first set of CID group identifiers.
.Example
PS>Get-FalconCidGroup -Ids <id>, <id>

Retrieve detailed information about CID groups <id> and <id>.
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
function Get-FalconCidGroupMember {
<#
.Synopsis
Search for CID group members
.Description
Requires 'mssp:read'.
.Parameter Ids
CID group identifier(s)
.Parameter CID
CID
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
.Example
PS>Get-FalconCidGroupMember -Ids <id>, <id>

List the members of CID groups <id> and <id>.
.Example
PS>Get-FalconCidGroupMember -CID <id> -Detailed

List the CID groups in which CID <id> is a member, along with its other members.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $CID,

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
            CID = 'cid'
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
.Description
Requires 'mssp:read'.
.Parameter Ids
Combined group identifier(s) [<cid_group_id>:<user_group_id>]
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
.Example
PS>Get-FalconGroupRole -Ids <cid>:<user_group_id>>, <cid>:<user_group_id>

List the role assignments for the groups with the combined identifiers <cid>:<user_group_id> and
<cid>:<user_group_id>.
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
.Description
Requires 'mssp:read'.
.Parameter Ids
Child CID identifier(s)
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
mssp:read
.Example
PS>Get-FalconMemberCid -All

List all available member CIDs.
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
.Description
Requires 'mssp:read'.
.Parameter Ids
User group identifier(s)
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
.Example
PS>Get-FalconUserGroup -All

Retrieve all user group identifiers.
.Example
PS>Get-FalconUserGroup -Ids <id>, <id>

Retrieve detailed information about user groups <id> and <id>.
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
.Description
Requires 'mssp:read'.
.Parameter Ids
User group identifier(s), to find group members
.Parameter UserId
A user identifier, to find group membership
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
.Example
PS>Get-FalconUserGroupMember -Id <id>

List the first set of members in user group <id>.
.Example
PS>Get-FalconUserGroupMember -UserId <id> -Detailed

List the user groups in which user <id> is a member, along with its other members.
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
function New-FalconCidGroup {
<#
.Synopsis
Create a CID group
.Description
Requires 'mssp:write'.
.Parameter Name
CID group name
.Parameter Description
CID group description
.Role
mssp:write
.Example
PS>New-FalconCidGroup -Name 'Manual Testing' -Description 'Manual Testing'

Create a CID group named 'Manual Testing'.
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
Create a user group
.Description
Requires 'mssp:write'.
.Parameter Name
User group name
.Parameter Description
User group description
.Role
mssp:write
.Example
PS>New-FalconUserGroup -Name 'Manual Testing' -Description 'Manual Testing'

Create a user group named 'Manual Testing'.
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
function Remove-FalconCidGroup {
<#
.Synopsis
Delete CID group(s)
.Description
Requires 'mssp:write'.
.Parameter CidGroupIds
CID group identifier(s)
.Role
mssp:write
.Example
PS>Remove-FalconCidGroup -Ids <id>, <id>

Delete CID groups <id> and <id>.
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
            Format   = @{
                Query = @('cid_group_ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconCidGroupMember {
<#
.Synopsis
Remove members from a CID group
.Description
Requires 'mssp:write'.
.Parameter Id
CID group identifier
.Parameter CIDs
CID(s)
.Role
mssp:write
.Example
PS>Remove-FalconCidGroupMember -Id <id> -CIDs <cid>, <cid>

Remove CIDs <cid> and <cid> from CID group <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:delete', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
Remove role(s) between a user group and CID group
.Description
Requires 'mssp:write'.
.Parameter CidGroupId
CID group identifier
.Parameter UserGroupId
User group identifier
.Parameter RoleIds
Role(s), or leave blank to remove user group/CID group association
.Role
mssp:write
.Example
PS>Remove-FalconGroupRole -CidGroupId <cid_group_id> -UserGroupId <user_group_id> -RoleIds <role_id>, <role_id>

Remove roles <role_id> and <role_id> between CID group <cid_group_id> and user group <user_group_id>.
.Example
PS>Remove-FalconGroupRole -CidGroupId <cid_group_id> -UserGroupId <user_group_id>

Remove association between CID group <cid_group_id> and user group <user_group_id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/mssp-roles/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $CidGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $UserGroupId,

        [Parameter(ParameterSetName = '/mssp/entities/mssp-roles/v1:delete', Position = 3)]
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
Remove user group(s)
.Description
Requires 'mssp:write'.
.Parameter Ids
User group identifier(s)
.Role
mssp:write
.Example
PS>Remove-FalconUserGroup -Ids <id>, <id>

Delete user groups <id> and <id>.
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
Remove members from a user group
.Description
Requires 'mssp:write'.
.Parameter Id
User group identifier
.Parameter UserIds
User identifier(s)
.Role
mssp:write
.Example
PS>Remove-FalconUserGroupMember -Id <id> -UserIds <uuid>, <uuid>

Remove users <uuid> and <uuid> from user group <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-group-members/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:delete', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:delete', Mandatory = $true,
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
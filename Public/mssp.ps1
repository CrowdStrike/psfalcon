function Add-FalconCidGroupMember {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:post', Mandatory = $true, Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Cids
    )
    begin {
        $Fields = @{ Id = 'cid_group_id' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('cid_group_id', 'cids') }}
        }
        Invoke-Falcon @Param
    }
}
function Add-FalconGroupRole {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('cid_group_id', 'user_group_id', 'role_ids') }}
        }
        Invoke-Falcon @Param
    }
}
function Add-FalconUserGroupMember {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('user_uuids', 'user_group_id') }}
        }
        Invoke-Falcon @Param
    }
}
function Edit-FalconCidGroup {
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
        $Fields = @{ Id = 'cid_group_id' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('description', 'cid_group_id', 'name') }}
        }
        Invoke-Falcon @Param
    }
}
function Edit-FalconUserGroup {
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
        $Fields = @{ Id = 'user_group_id' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('description', 'name', 'user_group_id') }}
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCidGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/cid-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/queries/cid-groups/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc', 'name.asc', 'name.desc')]
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
        $Fields = @{ Ids = 'cid_group_ids' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('cid_group_ids', 'offset', 'limit', 'name', 'sort') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconCidGroupMember {
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/cid-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Cid,

        [Parameter(ParameterSetName = '/mssp/queries/cid-group-members/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc')]
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
        $Fields = @{ Ids = 'cid_group_ids' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('cid_group_ids', 'offset', 'limit', 'sort', 'cid') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconGroupRole {
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
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('limit', 'ids', 'role_id', 'cid_group_id', 'sort', 'offset', 'user_group_id') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconMemberCid {
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/children/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/children/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/children/v1:get', Position = 1)]
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc')]
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
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Query = @('sort', 'ids', 'offset', 'limit') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconUserGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/user-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/queries/user-groups/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc', 'name.asc', 'name.desc')]
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
        $Fields = @{ Ids = 'user_group_ids' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('sort', 'offset', 'user_group_ids', 'limit', 'name') }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconUserGroupMember {
    [CmdletBinding(DefaultParameterSetName = '/mssp/queries/user-group-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Ids,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/mssp/queries/user-group-members/v1:get', Position = 2)]
        [ValidateSet('last_modified_timestamp.asc', 'last_modified_timestamp.desc')]
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('sort', 'offset', 'user_group_ids', 'limit', 'user_uuid') }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconCidGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Description
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Body = @{ resources = @('description', 'name') }}
        }
        Invoke-Falcon @Param
    }
}
function New-FalconUserGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Description
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{ Body = @{ resources = @('description', 'name') }}
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconCidGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{ Ids = 'cid_group_ids' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('cid_group_ids') }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconCidGroupMember {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/cid-group-members/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:delete', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/mssp/entities/cid-group-members/v1:delete', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Cids
    )
    begin {
        $Fields = @{ Id = 'cid_group_id' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('cid_group_id', 'cids') }}
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconGroupRole {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('cid_group_id', 'user_group_id', 'role_ids') }}
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconUserGroup {
    [CmdletBinding(DefaultParameterSetName = '/mssp/entities/user-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/mssp/entities/user-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{ Ids = 'user_group_ids' }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Query = @('user_group_ids') }
        }
        Invoke-Falcon @Param
    }
}
function Remove-FalconUserGroupMember {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{ Body = @{ resources = @('user_uuids', 'user_group_id') }}
        }
        Invoke-Falcon @Param
    }
}
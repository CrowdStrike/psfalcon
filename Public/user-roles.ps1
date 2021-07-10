function Add-FalconRole {
<#
.Synopsis
Assign one or more roles to a user
.Parameter UserId
User identifier
.Parameter Ids
One or more user roles
.Role
usermgmt:write
#>
    [CmdletBinding(DefaultParameterSetName = '/user-roles/entities/user-roles/v1:post')]
    param(
        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:post', Mandatory = $true)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:post', Mandatory = $true, Position = 2)]
        [array] $Ids
    )
    begin {
        @('UserId', 'Ids').foreach{
            if ($PSBoundParameters.$_) {
                # Rename parameter for API submission
                $Field = switch ($_) {
                    'UserId' { 'user_uuid' }
                    'Ids'    { 'roleIds' }
                }
                $PSBoundParameters.Add($Field, $PSBoundParameters.$_)
                [void] $PSBoundParameters.Remove($_)
            }
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
                Query = @('user_uuid')
                Body  = @{
                    root = @('roleIds')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconRole {
<#
.Synopsis
Display user available roles, information about specific user roles, or roles assigned to a user
.Parameter UserId
User Identifier
.Parameter Ids
One or more user roles
.Parameter Detailed
Retrieve detailed information
.Role
usermgmt:read
#>
    [CmdletBinding(DefaultParameterSetName = '/user-roles/queries/user-role-ids-by-cid/v1:get')]
    param(
        [Parameter(ParameterSetName = '/user-roles/queries/user-role-ids-by-user-uuid/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/user-roles/queries/user-role-ids-by-cid/v1:get')]
        [Parameter(ParameterSetName = '/user-roles/queries/user-role-ids-by-user-uuid/v1:get')]
        [switch] $Detailed
    )
    begin {
        if ($PSBoundParameters.UserId) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('user_uuid', $PSBoundParameters.UserId)
            [void] $PSBoundParameters.Remove('UserId')
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
                Query = @('ids', 'user_uuid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconRole {
<#
.Synopsis
Revoke one or more roles from a user
.Parameter UserId
User Identifier
.Parameter Ids
One or more user roles
.Role
usermgmt:write
#>
    [CmdletBinding(DefaultParameterSetName = '/user-roles/entities/user-roles/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:delete', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:delete', Mandatory = $true,
            Position = 2)]
        [array] $Ids
    )
    begin {
        if ($PSBoundParameters.UserId) {
            # Rename parameter for API submission
            $PSBoundParameters.Add('user_uuid', $PSBoundParameters.UserId)
            [void] $PSBoundParameters.Remove('UserId')
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
                Query = @('user_uuid', 'ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Add-FalconRole {
<#
.Synopsis
Assign one or more roles to a user
.Description
Requires 'usermgmt:write'.
.Parameter UserId
User identifier
.Parameter Ids
User role(s)
.Role
usermgmt:write
.Example
PS>Add-FalconRole -Ids falconhost_admin, intel_admin -UserId <id>

Assign 'falconhost_admin' and 'intel_admin' to user <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/user-roles/entities/user-roles/v1:post')]
    param(
        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $UserId,

        [Parameter(ParameterSetName = '/user-roles/entities/user-roles/v1:post', Mandatory = $true, Position = 2)]
        [array] $Ids
    )
    begin {
        $Fields = @{
            Ids    = 'roleIds'
            UserId = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
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
function Edit-FalconUser {
<#
.Synopsis
Modify a user's first or last name
.Description
Requires 'usermgmt:write'.
.Parameter Id
User identifier
.Parameter Firstname
First name
.Parameter Lastname
Last name
.Role
usermgmt:write
.Example
PS>Edit-FalconUser -Id <id> -FirstName Jane -LastName Doe

Set the first and last name for user <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/users/entities/users/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/users/entities/users/v1:patch', Position = 2)]
        [string] $Firstname,

        [Parameter(ParameterSetName = '/users/entities/users/v1:patch', Position = 3)]
        [string] $Lastname
    )
    begin {
        $Fields = @{
            Id = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('user_uuid')
                Body  = @{
                    root = @('firstName', 'lastName')
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
.Description
Requires 'usermgmt:read'.
.Parameter UserId
User Identifier
.Parameter Ids
User role(s)
.Parameter Detailed
Retrieve detailed information
.Role
usermgmt:read
.Example
PS>Get-FalconRole -Detailed

List available user roles, their descriptions and display names.
.Example
PS>Get-FalconRole -UserId <id>

List assigned user roles for user <id>.
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
        $Fields = @{
            UserId = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'user_uuid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUser {
<#
.Synopsis
List all User identifiers, display user identifiers by email or show detailed information about users
.Description
Requires 'usermgmt:read'.
.Parameter Ids
User identifier(s)
.Parameter Usernames
Username(s)
.Parameter Detailed
Retrieve detailed information
.Role
usermgmt:read
.Example
PS>Get-FalconUser -Detailed

List all users, their information and related identifiers.
.Example
PS>Get-FalconUser -Ids <id>, <id>

List information and related identifiers for users <id> and <id>.

#>
    [CmdletBinding(DefaultParameterSetName = '/users/queries/user-uuids-by-cid/v1:get')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/users/queries/user-uuids-by-email/v1:get', Mandatory = $true,
            Position = 2)]
        [array] $Usernames,

        [Parameter(ParameterSetName = '/users/queries/user-uuids-by-cid/v1:get')]
        [Parameter(ParameterSetName = '/users/queries/user-uuids-by-email/v1:get')]
        [switch] $Detailed
        
    )
    begin {
        $Fields = @{
            Usernames = 'uid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'uid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconUser {
<#
.Synopsis
Create a user
.Description
Requires 'usermgmt:write'.
.Parameter Username
Username
.Parameter Firstname
First name
.Parameter Lastname
Last name
.Parameter Password
If left blank, the user will be emailed a link to set their password (recommended)
.Role
usermgmt:write
.Example
PS>New-FalconUser -Username jane.doe@example.com

Create user 'jane.doe@example.com' and email them a link to set their password.
#>
    [CmdletBinding(DefaultParameterSetName = '/users/entities/users/v1:post')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Mandatory = $true, Position = 1)]
        [string] $Username,

        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Position = 2)]
        [string] $Firstname,

        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Position = 3)]
        [string] $Lastname,

        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Position = 4)]
        [string] $Password
    )
    begin {
        $Fields = @{
            Username = 'uid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('firstName', 'uid', 'password', 'lastName')
                }
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
.Description
Requires 'usermgmt:write'.
.Parameter UserId
User identifier
.Parameter Ids
User role(s)
.Role
usermgmt:write
.Example
PS>Remove-FalconRole -Ids falconhost_admin, intel_admin -UserId <id>

Remove 'falconhost_admin' and 'intel_admin' roles from user <id>.
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
        $Fields = @{
            UserId = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('user_uuid', 'ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconUser {
<#
.Synopsis
Delete a user
.Description
Requires 'usermgmt:write'.
.Parameter Id
User identifier
.Role
usermgmt:write
.Example
PS>Remove-FalconUser -Id <id>

Delete user <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/users/entities/users/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    begin {
        $Fields = @{
            Id = 'user_uuid'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('user_uuid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconUser {
<#
.Synopsis
Modify an existing users first or last name
.Parameter Id
User identifier
.Parameter Firstname
First name
.Parameter Lastname
Last name
.Role
usermgmt:write
#>
    [CmdletBinding(DefaultParameterSetName = '/users/entities/users/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:patch', Mandatory = $true, Position = 1)]
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Get-FalconUser {
<#
.Synopsis
List all User identifiers, display user identifiers by email or show detailed information about users
.Parameter Ids
One or more user identifiers
.Parameter Usernames
One or more usernames (typically email addresses)
.Parameter Detailed
Retrieve detailed information
.Role
usermgmt:read
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
Create a new user. After creating a user, assign one or more roles with 'Add-FalconRole'
.Parameter Username
Username (typically an email address)
.Parameter Firstname
First name
.Parameter Lastname
Last name
.Parameter Password
If left blank, the user will be emailed a link to set their password (recommended)
.Role
usermgmt:write
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
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Remove-FalconUser {
<#
.Synopsis
Delete a user permanently
.Parameter Id
User identifier
.Role
usermgmt:write
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
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('user_uuid')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
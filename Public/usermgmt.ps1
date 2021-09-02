function Add-FalconRole {
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
    }
    process {
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
        Invoke-Falcon @Param
    }
}
function Get-FalconRole {
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
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'user_uuid')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconUser {
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
    [CmdletBinding(DefaultParameterSetName = '/users/entities/users/v1:post')]
    param(
        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Mandatory = $true, Position = 1)]
        [string] $Username,

        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Position = 2)]
        [string] $Firstname,

        [Parameter(ParameterSetName = '/users/entities/users/v1:post', Position = 3)]
        [string] $Lastname
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
                    root = @('firstName', 'uid', 'lastName')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconRole {
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
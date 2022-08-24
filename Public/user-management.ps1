function Add-FalconRole {
<#
.SYNOPSIS
Assign roles to users
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER UserId
User identifier
.PARAMETER Id
User role
.PARAMETER Cid
Customer identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-roles/entities/user-roles/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('uuid','user_uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [Alias('Ids','roles')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [string]$Cid
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = if ($PSCmdlet.ParameterSetName -eq '/user-management/entities/user-role-actions/v1:post') {
                @{ Body = @{ root = @('cid','uuid','action','role_ids') }}
            } else {
                @{ Query = @('user_uuid'); Body = @{ root = @('roleIds') }}
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) { @($Id).foreach{ $List.Add($_) }}
    }
    end {
        if ($List) {
            if ($PSCmdlet.ParameterSetName -eq '/user-management/entities/user-role-actions/v1:post') {
                $PSBoundParameters['role_ids'] = @($List | Select-Object -Unique)
                $PSBoundParameters['uuid'] = $PSBoundParameters.UserId
                $PSBoundParameters['action'] = 'grant'
            } else {
                $PSBoundParameters['roleIds'] = @($List | Select-Object -Unique)
                $PSBoundParameters['user_uuid'] = $PSBoundParameters.UserId
            }
            [void]$PSBoundParameters.Remove('Id')
            [void]$PSBoundParameters.Remove('UserId')
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Edit-FalconUser {
<#
.SYNOPSIS
Modify the name of a user
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER FirstName
First name
.PARAMETER LastName
Last name
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Position=1)]
        [Alias('first_name')]
        [string]$FirstName,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Position=2)]
        [Alias('last_name')]
        [string]$LastName,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=3)]
        [Alias('user_uuid','uuid')]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('user_uuid')
                Body = @{ root = @('first_name','last_name') }
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconRole {
<#
.SYNOPSIS
Search for user roles and assignments
.DESCRIPTION
Requires 'User Management: Read'.
.PARAMETER Id
Role identifier
.PARAMETER UserId
User identifier
.PARAMETER Cid
Customer identifier

.PARAMETER Detailed
Retrieve detailed information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/queries/roles/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/roles/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Mandatory,Position=1)]
        [Alias('user_uuid','uuid')]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-management/queries/roles/v1:get',Position=1)]
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Cid,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=3)]
        [string]$Filter,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=4)]
        [ValidateSet('cid|asc','cid|desc','role_name|asc','role_name|desc','type|asc','type|desc',
            IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=5)]
        [ValidateRange(1,500)]
        [int]$Limit,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=6)]
        [string]$Offset,
        [Parameter(ParameterSetName='/user-management/combined/user-roles/v1:get',Position=7)]
        [Alias('direct_only')]
        [boolean]$DirectOnly,
        [Parameter(ParameterSetName='/user-management/queries/roles/v1:get')]
        [Parameter(ParameterSetName='/user-roles/queries/user-role-ids-by-cid/v1:get')]
        [switch]$Detailed
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','filter','user_uuid','limit','cid','direct_only','offset','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{
                if ($_ -match '^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$') {
                    Get-FalconRole -UserId $_
                } elseif ($_ -match '^[a-fA-F0-9]{32}$') {
                    Get-FalconRole -Cid $_
                } else {
                    $List.Add($_)
                }
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconUser {
<#
.SYNOPSIS
Search for users
.DESCRIPTION
Requires 'User Management: Read'.
.PARAMETER Id
User identifier
.PARAMETER Username
Username
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER Include
Include additional properties
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/queries/users/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/users/GET/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids','uuid')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-email/v1:get',Mandatory)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('uid','Usernames')]
        [string[]]$Username,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=1)]
        [string]$Filter,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=2)]
        [ValidateSet('first_name|asc','first_name|desc','last_name|asc','last_name|desc','name|asc','name|desc',
            'uid|asc','uid|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=3)]
        [ValidateRange(1,500)]
        [int]$Limit,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=4)]
        [int]$Offset,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
        [Parameter(ParameterSetName='/user-management/entities/users/GET/v1:post')]
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-email/v1:get')]
        [ValidateSet('roles',IgnoreCase=$false)]
        [string[]]$Include
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('ids') }
                Query = @('filter','sort','limit','offset','uid')
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
        if ($Request -and $Include) {
            if (!$Request.uuid) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ uuid = $_ }}}
            if ($Include -contains 'roles') {
                @($Request).foreach{ Set-Property $_ roles @(Get-FalconRole -UserId $_.uuid) }
            }
        }
        $Request
    }
}
function Invoke-FalconUserAction {
<#
.SYNOPSIS
Perform an action on a user
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER Name
Action name
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/entities/user-actions/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/user-actions/v1:post',Mandatory,Position=1)]
        [ValidateSet('reset_password','reset_2fa',IgnoreCase=$false)]
        [string]$Name,
        [Parameter(ParameterSetName='/user-management/entities/user-actions/v1:post',Mandatory,Position=2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('ids','action') }}
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            $PSBoundParameters['Action'] = @{ action_name = $PSBoundParameters.Name }
            [void]$PSBoundParameters.Remove('Name')
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function New-FalconUser {
<#
.SYNOPSIS
Create a user
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER Username
Username
.PARAMETER Firstname
First name
.PARAMETER Lastname
Last name
.PARAMETER Password
Password. If left unspecified, the user will be emailed a link to set their password.
.PARAMETER Cid
Customer identifier
.PARAMETER ValidateOnly
Validate if user is allowed but do not create them
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('uid')]
        [string]$Username,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
            Position=2)]
        [Alias('first_name')]
        [string]$FirstName,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [Alias('last_name')]
        [string]$LastName,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [ValidatePattern('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{12,}$')]
        [string]$Password,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
            Position=5)]
        [string]$Cid,
        [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
            Position=6)]
        [Alias('validate_only')]
        [boolean]$ValidateOnly
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('validate_only')
                Body = @{ root = @('first_name','uid','last_name','cid','password') }
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Remove-FalconRole {
<#
.SYNOPSIS
Remove roles from a user
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER UserId
User identifier
.PARAMETER Id
User role
.PARAMETER Cid
Customer identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-roles/entities/user-roles/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('uuid','user_uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
        [Alias('roleIds','Ids','roles')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=3)]
        [string]$Cid
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = if ($PSCmdlet.ParameterSetName -eq '/user-management/entities/user-role-actions/v1:post') {
                @{ Body = @{ root = @('cid','uuid','action','role_ids') }}
            } else {
                @{ Query = @('user_uuid','ids') }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) { @($Id).foreach{ $List.Add($_) }}
    }
    end {
        if ($List) {
            if ($PSCmdlet.ParameterSetName -eq '/user-management/entities/user-role-actions/v1:post') {
                $PSBoundParameters['role_ids'] = @($List | Select-Object -Unique)
                $PSBoundParameters['uuid'] = $PSBoundParameters.UserId
                $PSBoundParameters['action'] = 'revoke'
            } else {
                $PSBoundParameters['Ids'] = @($List | Select-Object -Unique)
                $PSBoundParameters['user_uuid'] = $PSBoundParameters.UserId
            }
            [void]$PSBoundParameters.Remove('Id')
            [void]$PSBoundParameters.Remove('UserId')
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Remove-FalconUser {
<#
.SYNOPSIS
Remove a user
.DESCRIPTION
Requires 'User Management: Write'.
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-management/entities/users/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Alias('user_uuid','uuid')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('user_uuid') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
@('Add-FalconRole','Remove-FalconRole').foreach{
    $Register = @{
        CommandName = $_
        ParameterName = 'Id'
        ScriptBlock = { Get-FalconRole -EA 0 }
    }
    Register-ArgumentCompleter @Register
}
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
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-roles/entities/user-roles/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('roleIds','Ids','roles')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('user_uuid')
                Body = @{ root = @('roleIds') }
            }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) { @($Id).foreach{ $List.Add($_) }}
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
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
.PARAMETER Firstname
First name
.PARAMETER Lastname
Last name
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/users/entities/users/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/users/entities/users/v1:patch',Position=1)]
        [string]$FirstName,
        [Parameter(ParameterSetName='/users/entities/users/v1:patch',Position=2)]
        [string]$LastName,
        [Parameter(ParameterSetName='/users/entities/users/v1:patch',Mandatory,ValueFromPipeline,
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
                Body = @{ root = @('firstName','lastName') }
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
User role
.PARAMETER UserId
User Identifier
.PARAMETER Detailed
Retrieve detailed information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-roles/queries/user-role-ids-by-cid/v1:get',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/user-roles/queries/user-role-ids-by-user-uuid/v1:get',Mandatory,
            ValueFromPipelineByPropertyName)]
        [Alias('user_uuid','uuid')]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-roles/queries/user-role-ids-by-cid/v1:get')]
        [Parameter(ParameterSetName='/user-roles/queries/user-role-ids-by-user-uuid/v1:get')]
        [switch]$Detailed
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','user_uuid') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{
                if ($_ -match '^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$') {
                    Get-FalconRole -UserId $_
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

User roles can be appended to the results using the 'Include' parameter.
.PARAMETER Include
Include additional properties
.PARAMETER Id
User identifier
.PARAMETER Username
Username
.PARAMETER Detailed
Retrieve detailed information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/users/queries/user-uuids-by-cid/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-cid/v1:get')]
        [Parameter(ParameterSetName='/users/entities/users/v1:get')]
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-email/v1:get')]
        [ValidateSet('roles',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-email/v1:get',Mandatory)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('uid','Usernames')]
        [string[]]$Username,
        [Parameter(ParameterSetName='/users/entities/users/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('Ids','uuid')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-cid/v1:get')]
        [Parameter(ParameterSetName='/users/queries/user-uuids-by-email/v1:get')]
        [switch]$Detailed
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','uid') }
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
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/users/entities/users/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/users/entities/users/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidateScript({
            if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
        })]
        [Alias('uid')]
        [string]$Username,
        [Parameter(ParameterSetName='/users/entities/users/v1:post',ValueFromPipelineByPropertyName,Position=2)]
        [string]$Firstname,
        [Parameter(ParameterSetName='/users/entities/users/v1:post',ValueFromPipelineByPropertyName,Position=3)]
        [string]$Lastname,
        [Parameter(ParameterSetName='/users/entities/users/v1:post',ValueFromPipelineByPropertyName,Position=4)]
        [ValidatePattern('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{12,}$')]
        [string]$Password
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('firstName','uid','lastName','password') }}
        }
    }
    process {
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
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
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Users-and-Roles
#>
    [CmdletBinding(DefaultParameterSetName='/user-roles/entities/user-roles/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid')]
        [string]$UserId,
        [Parameter(ParameterSetName='/user-roles/entities/user-roles/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [Alias('Ids','roles')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('user_uuid','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
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
    [CmdletBinding(DefaultParameterSetName='/users/entities/users/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/users/entities/users/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [Alias('user_uuid','uuid','Ids')]
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
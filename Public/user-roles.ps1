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
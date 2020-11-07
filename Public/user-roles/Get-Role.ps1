﻿function Get-Role {
    <#
    .SYNOPSIS
        Search for user roles, or roles assigned to a specific user
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'user-roles/GetAvailableRoleIds')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('user-roles/GetAvailableRoleIds', 'user-roles/GetRoles', 'user-roles/GetUserRoleIds')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $PSCmdlet.ParameterSetName
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'RoleIds'
                }
            }
            Invoke-Request @Param
        }
    }
}
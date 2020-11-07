function Add-Role {
    <#
    .SYNOPSIS
        Assign one or more roles to a user
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'user-roles/GrantUserRoleIds')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('user-roles/GrantUserRoleIds')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
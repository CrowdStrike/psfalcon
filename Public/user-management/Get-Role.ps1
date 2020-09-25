function Get-Role {
<#
.SYNOPSIS
    Search for user roles, or roles assigned to a specific user
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER DETAILED
    Retrieve detailed information
.PARAMETER ALL
    Repeat requests until all available results are retrieved
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'GetAvailableRoleIds')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'GetAvailableRoleIds',
            HelpMessage = 'Retrieve detailed information')]
        [switch] $Detailed,

        [Parameter(
            ParameterSetName = 'GetAvailableRoleIds',
            HelpMessage = 'Repeat requests until all available results are retrieved')]
        [switch] $All,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('GetAvailableRoleIds', 'GetRoles', 'GetUserRoleIds')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $PSCmdlet.ParameterSetName
                Entity = $Endpoints[1]
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
            # Evaluate input and make request
            Invoke-Request @Param
        }
    }
}

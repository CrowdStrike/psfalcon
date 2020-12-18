function Get-User {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'users/RetrieveUserUUIDsByCID')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('users/RetrieveUserUUIDsByCID', 'users/RetrieveUser', 'users/RetrieveUserUUID',
            'users/RetrieveEmailsByCID')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @('users/RetrieveEmailsByCID')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'Usernames' {
                    $Param.Query = $Endpoints[3]
                }
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = if ($Param.Query -eq $Endpoints[0]) {
                        'UserIds'
                    }
                    else {
                        'Username'
                    }
                }
            }
            Invoke-Request @Param
        }
    }
}
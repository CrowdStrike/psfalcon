function Get-User {
    <#
    .SYNOPSIS
        Retrieve user identifiers or usernames
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
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
                Query   = $PSCmdlet.ParameterSetName
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'UserIds'
                }
                'Names' {
                    $Param['Query'] = 'RetrieveEmailsByCID'
                }
            }
            Invoke-Request @Param
        }
    }
}
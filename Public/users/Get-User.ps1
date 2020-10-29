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
        # Endpoint(s) used by function
        $Endpoints = @('users/RetrieveUserUUIDsByCID', 'users/RetrieveUser', 'users/RetrieveUserUUID',
            'users/RetrieveEmailsByCID')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name @('users/RetrieveEmailsByCID')
        } else {
            # Evaluate input and make request
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

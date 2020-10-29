function Get-Session {
<#
.SYNOPSIS
    Retrieve Real-time Response sessions
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-ListAllSessions')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('real-time-response/RTR-ListAllSessions', 'real-time-response/RTR-ListSessions',
            'real-time-response/RTR-ListQueuedSessions')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query = $Endpoints[0]
                Entity = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'Queue' {
                    $Param.Entity = $Endpoints[2]
                    $Param['Modifier'] = 'Queue'
                }
                'Detailed' {
                    $Param['Detailed'] = 'SessionIds'
                }
                'All' {
                    $Param['All'] = $true
                }
            }
            Invoke-Request @Param
        }
    }
}
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
        $Endpoints = @('real-time-response/RTR-ListAllSessions', 'real-time-response/RTR-ListSessions',
            'real-time-response/RTR-ListQueuedSessions')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
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
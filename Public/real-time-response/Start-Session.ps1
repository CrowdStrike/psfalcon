function Start-Session {
    <#
    .SYNOPSIS
        Initialize a Real-time Response session with one or more hosts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-InitSession')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/RTR-InitSession', 'real-time-response/BatchInitSessions')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}
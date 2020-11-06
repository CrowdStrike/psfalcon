function Confirm-AdminCommand {
    <#
    .SYNOPSIS
        Check the status of an Admin Real-time Response command
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-CheckAdminCommandStatus')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/RTR-CheckAdminCommandStatus')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        if (-not($Dynamic.SequenceId.Value)) {
            $Dynamic.SequenceId.Value = 0
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Dynamic = $Dynamic
            }
            if ($PSBoundParameters.All) {
                $Param['All'] = $true
            }
            Invoke-Request @Param
        }
    }
}
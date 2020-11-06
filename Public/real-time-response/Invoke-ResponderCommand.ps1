function Invoke-ResponderCommand {
    <#
    .SYNOPSIS
        Issue a command to a Real-time Response session using Active Responder permissions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-ExecuteActiveResponderCommand')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/RTR-ExecuteActiveResponderCommand',
            'real-time-response/BatchActiveResponderCmd')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if ($Dynamic.Arguments.value) {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value) $($Dynamic.Arguments.value)"
            }
            else {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value)"
            }
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}
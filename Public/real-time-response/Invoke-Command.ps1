function Invoke-Command {
<#
.SYNOPSIS
    Issue a command to a Real-time Response session
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-ExecuteCommand')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-ExecuteCommand', 'BatchCmd')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Append 'base_command' to 'command_string'
            if ($Dynamic.Arguments.value) {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value) $($Dynamic.Arguments.value)"
            } else {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value)"
            }
            # Evaluate input and make request
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}
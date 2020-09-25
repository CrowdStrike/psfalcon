function Invoke-ResponderCommand {
<#
.SYNOPSIS
    Issue a command to a Real-time Response session using Active Responder permissions
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'RTR-ExecuteActiveResponderCommand')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('RTR-ExecuteActiveResponderCommand', 'BatchActiveResponderCmd')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
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
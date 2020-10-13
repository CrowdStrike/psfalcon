function Invoke-Command {
<#
.SYNOPSIS
    Issue or execute a command using Real-time Response
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'CustomRTR')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('CustomRTR', 'RTR-ExecuteCommand', 'CustomRTRBatch', 'BatchCmd')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Join 'base_command' and 'command_string'
            if ($Dynamic.Arguments.value) {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value) $($Dynamic.Arguments.value)"
            } else {
                $Dynamic.Arguments.value = "$($Dynamic.Command.value)"
            }
            if ($PSBoundParameters.HostId) {
                # Create a session and issue command
                $Param = @{
                    HostId = $PSBoundParameters.HostId
                    Command = $PSBoundParameters.Command
                }
                switch ($PSBoundParameters.Keys) {
                    'Arguments' { $Param['Arguments'] = $PSBoundParameters.Arguments }
                    'QueueOffline' { $Param['QueueOffline'] = $PSBoundParameters.QueueOffline }
                }
                Invoke-RTR @Param
            } elseif ($PSBoundParameters.HostIds) {
                # Create a batch session and issue command
                $Param = @{
                    HostIds = $PSBoundParameters.HostIds
                    Command = $PSBoundParameters.Command
                }
                switch ($PSBoundParameters.Keys) {
                    'Arguments' { $Param['Arguments'] = $PSBoundParameters.Arguments }
                    'Timeout' { $Param['Timeout'] = $PSBoundParameters.Timeout }
                    'QueueOffline' { $Param['QueueOffline'] = $PSBoundParameters.QueueOffline }
                }
                Invoke-RTRBatch @Param
            } elseif ($PSBoundParameters.SessionId) {
                # Evaluate input and make request
                Invoke-Request -Query $Endpoints[1] -Dynamic $Dynamic
            } elseif ($PSBoundParameters.BatchId) {
                # Evaluate input and make request
                Invoke-Request -Query $Endpoints[2] -Dynamic $Dynamic
            } else {
                Write-Error "Must provide one or more Host identifiers, or an existing Session identifier"
            }
        }
    }
}
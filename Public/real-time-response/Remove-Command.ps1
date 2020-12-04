﻿function Remove-Command {
    <#
    .SYNOPSIS
        Remove a queued Real-time Response command
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'real-time-response/RTR-DeleteQueuedSession')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('real-time-response/RTR-DeleteQueuedSession')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
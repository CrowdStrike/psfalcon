﻿function Receive-Installer {
    <#
    .SYNOPSIS
        Download a sensor installer package
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'sensors/DownloadSensorInstallerById')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('sensors/DownloadSensorInstallerById')
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
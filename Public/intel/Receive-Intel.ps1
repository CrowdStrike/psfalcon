﻿function Receive-Intel {
    <#
    .SYNOPSIS
        Download a threat intelligence report PDF
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'intel/GetIntelReportPDF')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('intel/GetIntelReportPDF')
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
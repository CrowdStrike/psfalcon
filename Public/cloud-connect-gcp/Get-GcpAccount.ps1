﻿function Get-GcpAccount {
    <#
    .SYNOPSIS
        List registered GCP accounts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-gcp/GetCSPMCGPAccount')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-gcp/GetCSPMCGPAccount')
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
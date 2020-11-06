﻿function Edit-AzureAccount {
    <#
    .SYNOPSIS
        Update an Azure service account
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-azure/UpdateCSPMAzureAccountClientID')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-azure/UpdateCSPMAzureAccountClientID')
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
﻿function Get-MalQuerySample {
    <#
    .SYNOPSIS
        Retrieve indexed file metadata by SHA256 hash
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/GetMalQueryMetadataV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/GetMalQueryMetadataV1')
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
﻿function Edit-FirewallGroup {
    <#
    .SYNOPSIS
        Update a Firewall Rule Group
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/update-rule-group')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/update-rule-group')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param $Endpoints[0] $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.id)"
                }
                $Param.Body['diff_type'] = 'application/json-patch+json'
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
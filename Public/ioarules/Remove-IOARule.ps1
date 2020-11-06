﻿function Remove-IOARule {
    <#
    .SYNOPSIS
        Remove custom Indicator of Attack rules
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/delete-rules')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('ioarules/delete-rules')
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
                Invoke-Endpoint @Param
            }
        }
    }
}
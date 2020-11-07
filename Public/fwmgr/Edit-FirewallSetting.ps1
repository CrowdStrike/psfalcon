function Edit-FirewallSetting {
    <#
    .SYNOPSIS
        Update settings applied to Firewall policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/update-policy-container')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/update-policy-container')
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
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
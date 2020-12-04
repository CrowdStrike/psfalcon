function Remove-FirewallGroup {
    <#
    .SYNOPSIS
        Remove Firewall Rule Groups
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/delete-rule-groups')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/delete-rule-groups')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.id)"
                }
                Invoke-Endpoint @Param
            }
        }
    }
}
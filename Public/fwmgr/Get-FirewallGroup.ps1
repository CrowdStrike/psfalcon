function Get-FirewallGroup {
    <#
    .SYNOPSIS
        Search for firewall rule groups
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/query-rule-groups')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/query-rule-groups', 'fwmgr/get-rule-groups')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = 'GroupIds'
                }
            }
            Invoke-Request @Param
        }
    }
}
function Get-FirewallPlatform {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/query-platforms')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/query-platforms', 'fwmgr/get-platforms')
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
                'Detailed' {
                    $Param['Detailed'] = 'PlatformIds'
                }
            }
            Invoke-Request @Param
        }
    }
}

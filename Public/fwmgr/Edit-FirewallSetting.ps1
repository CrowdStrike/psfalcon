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
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
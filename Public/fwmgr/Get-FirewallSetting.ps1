function Get-FirewallSetting {
    <#
    .SYNOPSIS
        Retrieve settings applied to Firewall policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/get-policy-containers')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('fwmgr/get-policy-containers')
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
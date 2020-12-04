function Set-FirewallPrecedence {
    <#
    .SYNOPSIS
        Set the precedence of Firewall policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/setFirewallPoliciesPrecedence')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/setFirewallPoliciesPrecedence')
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
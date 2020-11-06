function Remove-FirewallGroup {
    <#
    .SYNOPSIS
        Remove Firewall Rule Groups
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
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
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
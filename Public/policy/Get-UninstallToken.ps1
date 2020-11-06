function Get-UninstallToken {
    <#
    .SYNOPSIS
        Return the uninstall token for a specific device, or the bulk maintenance token
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/revealUninstallToken')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/revealUninstallToken')
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
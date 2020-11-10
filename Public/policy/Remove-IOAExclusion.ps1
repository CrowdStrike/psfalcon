function Remove-IOAExclusion {
    <#
    .SYNOPSIS
        Remove Indicator of Attack exclusions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/deleteIOAExclusionsV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/deleteIOAExclusionsV1')
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
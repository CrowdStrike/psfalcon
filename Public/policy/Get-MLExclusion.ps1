function Get-MLExclusion {
    <#
    .SYNOPSIS
        Retrieve information about Machine Learning exclusions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/GetMLExclusionsv1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/GetMLExclusionsv1')
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
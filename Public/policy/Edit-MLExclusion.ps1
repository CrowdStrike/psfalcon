function Edit-MLExclusion {
    <#
    .SYNOPSIS
        Modify a Machine Learning exclusion
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/updateMLExclusionsV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/updateMLExclusionsV1')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
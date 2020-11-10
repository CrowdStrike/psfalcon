function Get-SVExclusion {
    <#
    .SYNOPSIS
        Retrieve information about Sensor Visibility exclusions
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/GetSensorVisibilityExclusionsv1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/GetSensorVisibilityExclusionsv1')
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
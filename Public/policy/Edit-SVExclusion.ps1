function Edit-SVExclusion {
    <#
    .SYNOPSIS
        Modify a Sensor Visibility exclusion
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/updateSensorVisibilityExclusionsV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/updateSensorVisibilityExclusionsV1')
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
function Remove-SensorUpdatePolicy {
    <#
    .SYNOPSIS
        Remove Sensor Update Policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/deleteSensorUpdatePolicies')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/deleteSensorUpdatePolicies')
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
function Get-SensorUpdatePolicyMember {
    <#
    .SYNOPSIS
        Search for Sensor Update policy members
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/querySensorUpdatePolicyMembers')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/querySensorUpdatePolicyMembers', 'policy/queryCombinedSensorUpdatePolicyMembers')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                'policy/queryCombinedSensorUpdatePolicyMembers')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Dynamic = $Dynamic
            }
            if ($PSBoundParameters.All) {
                $Param['All'] = $true
            }
            if ($PSBoundParameters.Detailed) {
                $Param['Detailed'] = 'Combined'
                $Param.Query = $Endpoints[1]
            }
            Invoke-Request @Param
        }
    }
}
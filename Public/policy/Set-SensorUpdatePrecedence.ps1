function Set-SensorUpdatePrecedence {
    <#
    .SYNOPSIS
        Set the precedence of Sensor Update policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/setSensorUpdatePoliciesPrecedence')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/setSensorUpdatePoliciesPrecedence')
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
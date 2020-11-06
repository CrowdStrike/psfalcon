function New-DeviceControlPolicy {
    <#
    .SYNOPSIS
        Create Device Control Policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/createDeviceControlPolicies')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/createDeviceControlPolicies', 'private/Array')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif ($PSBoundParameters.Array) {
            $Param = @{
                Endpoint = $Endpoints[0]
                Body     = @{ resources = $PSBoundParameters.Array }
            }
            Format-Param -Param $Param
            Invoke-Endpoint @Param
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}

function Invoke-HostGroupAction {
    <#
    .SYNOPSIS
        Perform actions on Host Groups
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'devices/performGroupAction')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('devices/performGroupAction')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Max = 500
        $Dynamic.GroupId.value = @( $Dynamic.GroupId.Value )
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Inputs = $Dynamic.FilterValue.value
            for ($i = 0; $i -lt $Inputs.count; $i += $Max) {
                $Dynamic.FilterValue.value = $Inputs[$i..($i + ($Max - 1))]
                $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
                $Param.Body.action_parameters[0] = @{
                    name  = 'filter'
                    value = ("($($Param.Body.action_parameters[0].name):" +
                        "$(($Param.Body.action_parameters[0].value | ForEach-Object { "'$_'" }) -join ','))")
                }
                Format-Param -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}

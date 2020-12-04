function Invoke-PreventionPolicyAction {
    <#
    .SYNOPSIS
        Perform actions on Prevention policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/performPreventionPoliciesAction')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/performPreventionPoliciesAction')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param.Body.ids = @( $Param.Body.ids )
            if ($Param.Body.action_parameters) {
                $Param.Body.action_parameters[0].Add('name', 'group_id')
            }
            Format-Param -Param $Param
            Invoke-Endpoint @Param
        }
    }
}

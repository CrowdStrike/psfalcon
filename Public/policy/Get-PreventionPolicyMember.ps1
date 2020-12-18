function Get-PreventionPolicyMember {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/queryPreventionPolicyMembers')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/queryPreventionPolicyMembers', 'policy/queryCombinedPreventionPolicyMembers')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                'policy/queryCombinedPreventionPolicyMembers')
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
function Get-PreventionPolicy {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'policy/queryPreventionPolicies')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('policy/queryPreventionPolicies', 'policy/getPreventionPolicies',
            'policy/queryCombinedPreventionPolicies')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                'policy/queryCombinedPreventionPolicies')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            if ($PSBoundParameters.All) {
                $Param['All'] = $true
            }
            if ($PSBoundParameters.Detailed) {
                $Param['Detailed'] = 'Combined'
                $Param.Query = $Endpoints[2]
            }
            Invoke-Request @Param
        }
    }
}
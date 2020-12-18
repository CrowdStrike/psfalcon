function Get-HorizonPolicy {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'settings/GetCSPMPolicySettings')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('settings/GetCSPMPolicySettings', 'settings/GetCSPMPolicy')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            if ($PSBoundParameters.Service) {
                $Request = Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
                if ($PSBoundParameters.Detailed) {
                    & $MyInvocation.MyCommand.Name -PolicyIds $Request.policy_id
                }
                else {
                    $Request
                }
            }
            else {
                Invoke-Request -Query $Endpoints[1] -Dynamic $Dynamic
            }
        }
    }
}
function Edit-HorizonPolicy {
    <#
    .SYNOPSIS
        Update Falcon Horizon policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'settings/UpdateCSPMPolicySettings')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('settings/UpdateCSPMPolicySettings')
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
function Get-HorizonSetting {
    <#
    .SYNOPSIS
        Retrieve settings applied to Horizon policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'settings/GetCSPMPolicySettings')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('settings/GetCSPMPolicySettings')
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
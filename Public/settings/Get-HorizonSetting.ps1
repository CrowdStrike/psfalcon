function Get-HorizonSetting {
    <#
    .SYNOPSIS
        Retrieve settings applied to Horizon policies
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
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
        elseif ((-not($PSBoundParameters.Service)) -and (-not($PSBoundParameters.PolicyId))) {
            throw "Must provide either a Service or PolicyId value."
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
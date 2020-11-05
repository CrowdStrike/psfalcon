function Edit-FirewallSetting {
<#
.SYNOPSIS
    Update settings applied to Firewall policies
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/update-policy-container')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('fwmgr/update-policy-container')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
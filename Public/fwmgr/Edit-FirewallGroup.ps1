function Edit-FirewallGroup {
<#
.SYNOPSIS
    Update a Firewall Rule Group
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'fwmgr/update-rule-group')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('fwmgr/update-rule-group')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input
            $Param = Get-Param $Endpoints[0] $Dynamic

            # Force 'diff_type' into request body
            $Param.Body['diff_type'] = 'application/json-patch+json'

            # Convert to Json
            Format-Param $Param

            # Make request
            $Param # Invoke-Endpoint @Param
        }
    }
}
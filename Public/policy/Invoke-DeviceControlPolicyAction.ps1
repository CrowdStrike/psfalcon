function Invoke-DeviceControlPolicyAction {
<#
.SYNOPSIS
    Perform actions on Device Control policies
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'policy/performDeviceControlPoliciesAction')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('policy/performDeviceControlPoliciesAction')

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

            # Convert 'ids' to an array
            $Param.Body.ids = @( $Param.Body.ids )

            if ($Param.Body.action_parameters) {
                # Add 'name' to action_parameters
                $Param.Body.action_parameters[0].Add('name', 'group_id')
            }
            # Convert body to Json
            Format-Param $Param

            # Make request
            Invoke-Endpoint @Param
        }
    }
}

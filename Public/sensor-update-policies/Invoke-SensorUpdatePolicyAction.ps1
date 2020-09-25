function Invoke-SensorUpdatePolicyAction {
<#
.SYNOPSIS
    Perform actions on Sensor Update policies
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'performSensorUpdatePoliciesAction')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('performSensorUpdatePoliciesAction')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
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

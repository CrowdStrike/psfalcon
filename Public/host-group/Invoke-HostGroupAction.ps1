function Invoke-HostGroupAction {
<#
.SYNOPSIS
    Perform actions on Host Groups
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'performGroupAction')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('performGroupAction')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Maximum number of values per request
        $Max = 500

        # Convert GroupId to array
        $Dynamic.GroupId.value = @( $Dynamic.GroupId.Value )
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Gather all FilterValue input
            $Inputs = $Dynamic.FilterValue.value

            for ($i = 0; $i -lt $Inputs.count; $i += $Max) {
                # Split into groups of $Max
                $Dynamic.FilterValue.value = $Inputs[$i..($i + ($Max - 1))]

                # Evaluate input
                $Param = Get-Param $Endpoints[0] $Dynamic

                # Re-format action_parameters
                $Param.Body.action_parameters[0] = @{
                    name = 'filter'
                    value = ("($($Param.Body.action_parameters[0].name):" +
                        "$(($Param.Body.action_parameters[0].value | ForEach-Object { "'$_'" }) -join ','))")
                }
                # Convert body to Json
                Format-Param $Param

                # Make requests
                Invoke-Endpoint @Param
            }
        }
    }
}

function Invoke-HostAction {
<#
.SYNOPSIS
    Perform actions on Hosts
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PerformActionV2')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PerformActionV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints[0] -OutVariable Dynamic)
    }
    begin {
        # Set maximum number of identifiers in requests
        $Max = if ($Dynamic.ActionName.value -match '(hide_host|unhide_host)') {
            100
        } else {
            500
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input and make requests in groups of $Max
            foreach ($Param in (Get-Param $Endpoints[0] $Dynamic $Max)) {
                # Convert body to Json
                Format-Param $Param

                # Make request
                Invoke-Endpoint @Param
            }
        }
    }
}

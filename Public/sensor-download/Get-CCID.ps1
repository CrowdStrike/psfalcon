function Get-CCID {
<#
.SYNOPSIS
    Retrieve your customer identifier and checksum
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'GetSensorInstallersCCIDByQuery')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('GetSensorInstallersCCIDByQuery')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Make request
            Invoke-Endpoint -Endpoint $Endpoints[0]
        }
    }
}
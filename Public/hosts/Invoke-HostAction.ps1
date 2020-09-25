function Invoke-HostAction {
<#
.SYNOPSIS
    Perform actions on Hosts
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PerformActionV2')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PerformActionV2')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints[0] -OutVariable Dynamic)
    }
    begin {
        # Set maximum number of identifiers in each request
        $Max = if ($Dynamic.ActionName.value -match '(hide_host|unhide_host)') {
            100
        } else {
            500
        }
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param $Endpoints[0] $Dynamic $Max)) {
                # Convert body to Json
                Format-Param $Param

                # Make requests
                Invoke-Endpoint @Param
            }
        }
    }
}

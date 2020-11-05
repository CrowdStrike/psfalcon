function New-IOARule {
<#
.SYNOPSIS
    Create a custom Indicator of Attack rule
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'ioarules/create-rule')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('ioarules/create-rule')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param $Endpoints[0] $Dynamic)) {
                # Add Header parameter with api-client-id
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.id)"
                }
                # Make request
                Invoke-Endpoint @Param
            }
        }
    }
}
function Get-MalQueryQuota {
<#
.SYNOPSIS
    Get MalQuery search and download quotas
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'malquery/GetMalQueryQuotasV1')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('malquery/GetMalQueryQuotasV1')

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
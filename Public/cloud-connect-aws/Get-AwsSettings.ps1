function Get-AwsSettings {
<#
.SYNOPSIS
    Retrieve a set of Global Settings which are applicable to all provisioned AWS accounts
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'GetAWSSettings')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('GetAWSSettings')

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
function Edit-PreventionPolicy {
<#
.SYNOPSIS
    Update Prevention Policies
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'policy/updatePreventionPolicies')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('policy/updatePreventionPolicies', 'private/Array')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } elseif ($PSBoundParameters.Array) {
            # Build body from array
            $Param = @{
                Endpoint = $Endpoints[0]
                Body = @{ resources = $PSBoundParameters.Array }
            }
            # Convert Body to Json
            Format-Param $Param

            # Make request
            Invoke-Endpoint @Param
        } else {
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}

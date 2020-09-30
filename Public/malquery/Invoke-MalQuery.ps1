function Invoke-MalQuery {
<#
.SYNOPSIS
    Perform a MalQuery search
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'PostMalQueryExactSearchV1')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('PostMalQueryExactSearchV1', 'PostMalQueryFuzzySearchV1', 'PostMalQueryHuntV1')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            # Evaluate input
            $Param = Get-Param $PSCmdlet.ParameterSetName $Dynamic

            if ($Param.Body.options) {
                # Convert options from array to hashtable
                $Param.Body.options = $Param.Body.options[0]
            }
            # Convert to Json
            Format-Param $Param

            # Make request
            Invoke-Endpoint @Param
        }
    }
}
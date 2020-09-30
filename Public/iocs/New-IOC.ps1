function New-IOC {
<#
.SYNOPSIS
    Create custom IOCs
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'CreateIOC')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('CreateIOC', 'Array')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Maximum number of IOCs per request
        $Max = 200
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } elseif ($PSBoundParameters.Array) {
            # Make requests in groups of $Max
            for ($i = 0; $i -lt ($PSBoundParameters.Array).count; $i += $Max) {
                # Build body from array
                $Param = @{
                    Endpoint = $Endpoints[0]
                    Body = $PSBoundParameters.Array[$i..($i + ($Max -1))]
                }
                # Convert Body to Json
                Format-Param $Param

                # Make request
                Invoke-Endpoint @Param
            }
        } else {
            # Evaluate input
            $Param = Get-Param $Endpoints[0] $Dynamic

            # Force body into an array
            $Param.Body = @( $Param.Body )

            # Convert to Json
            Format-Param $Param

            # Make request
            Invoke-Endpoint @Param
        }
    }
}

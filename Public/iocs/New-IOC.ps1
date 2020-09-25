function New-IOC {
<#
.SYNOPSIS
    Create custom IOCs
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER ARRAY
    An array of custom IOCs to create
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'CreateIOC')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'Array',
            HelpMessage = 'An array of custom IOCs to create',
            Mandatory = $true)]
        [array] $Array,

        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('CreateIOC')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    begin {
        # Maximum number of IOCs per request
        $Max = 200
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($Array) {
                for ($i = 0; $i -lt $Array.count; $i += $Max) {
                    # Build body from array
                    $Param = @{
                        Endpoint = $Endpoints[0]
                        Body = $Array[$i..($i + ($Max -1))]
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
}

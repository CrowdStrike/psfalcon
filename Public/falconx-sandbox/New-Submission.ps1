function New-Submission {
<#
.SYNOPSIS
    Submit an uploaded file or URL for sandbox analysis
.DESCRIPTION
    Additional information is available with the -Help parameter
.PARAMETER HELP
    Output dynamic help information
.LINK
    https://github.com/bk-CS/PSFalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'Submit')]
    [OutputType()]
    param(
        [Parameter(
            ParameterSetName = 'DynamicHelp',
            Mandatory = $true)]
        [switch] $Help
    )
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('Submit')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($Help) {
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($Dynamic.Url.value -and $Dynamic.Sha256.value) {
                throw "Url and Sha256 cannot be combined in a submission."
            }
            if ($Dynamic.EnvironmentId.value) {
                # Convert EnvironmentId to integer value
                $Dynamic.EnvironmentId.value = switch ($Dynamic.EnvironmentId.value) {
                    'Android' {
                        200
                    }
                    'Ubuntu16_x64' {
                        300
                    }
                    'Win7_x64' {
                        110
                    }
                    'Win7_x86' {
                        100
                    }
                    'Win10_x64' {
                        160
                    }
                }
            }
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}

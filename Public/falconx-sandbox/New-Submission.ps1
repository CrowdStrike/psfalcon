function New-Submission {
<#
.SYNOPSIS
    Submit an uploaded file or URL for sandbox analysis
.DESCRIPTION
    Additional information is available with the -Help parameter
.LINK
    https://github.com/CrowdStrike/psfalcon
#>
    [CmdletBinding(DefaultParameterSetName = 'Submit')]
    [OutputType()]
    param()
    DynamicParam {
        # Endpoint(s) used by function
        $Endpoints = @('Submit')

        # Create runtime dictionary
        return (Get-Dictionary $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            # Output help information
            Get-DynamicHelp $MyInvocation.MyCommand.Name
        } else {
            if ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
                # Output exception if both Url and Sha256 are present
                throw "Url and Sha256 cannot be combined in a submission."
            }
            if ($Dynamic.EnvironmentId.value) {
                # Convert EnvironmentId to integer value
                $Dynamic.EnvironmentId.value = switch ($Dynamic.EnvironmentId.value) {
                    'Android' { 200 }
                    'Ubuntu16_x64' { 300 }
                    'Win7_x64' { 110 }
                    'Win7_x86' { 100 }
                    'Win10_x64' { 160 }
                }
            }
            # Evaluate input and make request
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}

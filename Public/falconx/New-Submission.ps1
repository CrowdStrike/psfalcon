function New-Submission {
    <#
    .SYNOPSIS
        Submit an uploaded file or URL for sandbox analysis
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'falconx/Submit')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('falconx/Submit')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
            throw "Url and Sha256 cannot be combined in a submission."
        }
        else {
            if ($Dynamic.EnvironmentId.value) {
                $Dynamic.EnvironmentId.value = switch ($Dynamic.EnvironmentId.value) {
                    'Android' { 200 }
                    'Ubuntu16_x64' { 300 }
                    'Win7_x64' { 110 }
                    'Win7_x86' { 100 }
                    'Win10_x64' { 160 }
                }
            }
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}

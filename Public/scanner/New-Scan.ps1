function New-Scan {
    <#
    .SYNOPSIS
        Submit one or more files to analyze using machine learning
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scanner/ScanSamples')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scanner/ScanSamples')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
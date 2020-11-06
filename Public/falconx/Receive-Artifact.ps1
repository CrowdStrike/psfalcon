function Receive-Artifact {
    <#
    .SYNOPSIS
        Download IOC packs, PCAP files, and other analysis artifacts
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'falconx/GetArtifacts')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('falconx/GetArtifacts')
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
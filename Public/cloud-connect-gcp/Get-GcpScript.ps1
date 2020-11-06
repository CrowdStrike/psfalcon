function Get-GcpScript {
    <#
    .SYNOPSIS
        Provides a script to run in a GCP environment to grant access to the Falcon platform
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'cloud-connect-gcp/GetCSPMGCPUserScripts')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('cloud-connect-gcp/GetCSPMGCPUserScripts')
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
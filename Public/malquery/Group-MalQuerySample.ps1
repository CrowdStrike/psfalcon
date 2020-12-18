function Group-MalQuerySample {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/PostMalQueryEntitiesSamplesMultidownloadV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/PostMalQueryEntitiesSamplesMultidownloadV1')
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
function Receive-MalQuerySample {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/GetMalQueryDownloadV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/GetMalQueryDownloadV1', 'malquery/GetMalQueryEntitiesSamplesFetchV1')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Request -Query $PSCmdlet.ParameterSetName -Dynamic $Dynamic
        }
    }
}
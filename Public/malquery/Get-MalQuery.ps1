function Get-MalQuery {
    <#
    .SYNOPSIS
        Get the status or results of a hunt, search or sample archive request
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/GetMalQueryRequestV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/GetMalQueryRequestV1')
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
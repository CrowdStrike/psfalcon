function Get-MalQueryQuota {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/GetMalQueryQuotasV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/GetMalQueryQuotasV1')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            Invoke-Endpoint -Endpoint $Endpoints[0]
        }
    }
}
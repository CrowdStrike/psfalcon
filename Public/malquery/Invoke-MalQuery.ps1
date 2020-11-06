function Invoke-MalQuery {
    <#
    .SYNOPSIS
        Perform a MalQuery search
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'malquery/PostMalQueryExactSearchV1')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('malquery/PostMalQueryExactSearchV1', 'malquery/PostMalQueryFuzzySearchV1',
            'malquery/PostMalQueryHuntV1')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = Get-Param -Endpoint $PSCmdlet.ParameterSetName -Dynamic $Dynamic
            if ($Param.Body.options) {
                $Param.Body.options = $Param.Body.options[0]
            }
            Format-Param -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
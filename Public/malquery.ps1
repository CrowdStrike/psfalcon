function Get-MalQuery {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/entities/requests/v1:get')
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
function Get-MalQueryQuota {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/malquery/aggregates/quotas/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/aggregates/quotas/v1:get')
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
function Get-MalQuerySample {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/entities/metadata/v1:get')
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
function Group-MalQuerySample {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding()]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/entities/samples-multidownload/v1:post')
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
function Invoke-MalQuery {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/malquery/queries/exact-search/v1:post')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/queries/exact-search/v1:post', '/malquery/combined/fuzzy-search/v1:post',
            '/malquery/queries/hunt/v1:post')
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
            Format-Body -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
function Receive-MalQuerySample {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/malquery/entities/download-files/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/malquery/entities/download-files/v1:get', '/malquery/entities/samples-fetch/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Endpoint = if ($Dynamic.Id.Value -match '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}') {
                $Endpoints[1]
            }
            else {
                $Endpoints[0]
            }
            Invoke-Request -Query $Endpoint -Dynamic $Dynamic
        }
    }
}
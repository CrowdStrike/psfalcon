function Edit-InstallToken {
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
        $Endpoints = @('/installation-tokens/entities/tokens/v1:patch')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
function Get-InstallToken {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/tokens/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/installation-tokens/queries/tokens/v1:get', '/installation-tokens/entities/tokens/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All'      { $Param['All'] = $true }
                'Total'    { $Param['Total'] = $true }
                'Detailed' { $Param['Detailed'] = $true }
            }
            Invoke-Request @Param
        }
    }
}
function Get-InstallTokenEvent {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/queries/audit-events/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/installation-tokens/queries/audit-events/v1:get',
            '/installation-tokens/entities/audit-events/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All'      { $Param['All'] = $true }
                'Total'    { $Param['Total'] = $true }
                'Detailed' { $Param['Detailed'] = $true }
            }
            Invoke-Request @Param
        }
    }
}
function Get-InstallTokenSettings {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/installation-tokens/entities/customer-settings/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/installation-tokens/entities/customer-settings/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            Invoke-Endpoint -Endpoint $Endpoints[0]
        }
    }
}
function New-InstallToken {
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
        $Endpoints = @('/installation-tokens/entities/tokens/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
function Remove-InstallToken {
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
        $Endpoints = @('/installation-tokens/entities/tokens/v1:delete')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
function Edit-ReconAction {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:patch')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/actions/v1:patch')
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
function Edit-ReconRule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:patch')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/rules/v1:patch', 'script:EditReconRuleArray')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            if ($PSBoundParameters.Array) {
                $Param['Body'] = @( $PSBoundParameters.Array )
            } else {
                $Param.Body = @( $Param.Body )
            }
            Format-Body -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
function Get-ReconAction {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/actions/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/queries/actions/v1:get', '/recon/entities/actions/v1:get')
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
function Get-ReconNotification {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/notifications/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/queries/notifications/v1:get', '/recon/entities/notifications/v1:get',
            '/recon/entities/notifications-detailed/v1:get',
            '/recon/entities/notifications-detailed-translated/v1:get',
            '/recon/entities/notifications-translated/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = if ($PSCmdlet.ParameterSetName -match '/entities/') {
                    $PSCmdlet.ParameterSetName
                } else {
                    $Endpoints[1]
                }
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
function Get-ReconRule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/queries/rules/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/queries/rules/v1:get', '/recon/entities/rules/v1:get')
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
function New-ReconAction {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:post')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/actions/v1:post')
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
function New-ReconRule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:post')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/rules/v1:post', 'script:CreateReconRuleArray')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            if ($PSBoundParameters.Array) {
                $Param['Body'] = @( $PSBoundParameters.Array )
            } else {
                $Param.Body = @( $Param.Body )
            }
            Format-Body -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
function Remove-ReconAction {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/actions/v1:delete')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/actions/v1:delete')
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
function Remove-ReconRule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/recon/entities/rules/v1:delete')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/recon/entities/rules/v1:delete')
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
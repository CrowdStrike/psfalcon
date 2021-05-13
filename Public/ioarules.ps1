function Edit-IOAGroup {
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
        $Endpoints = @('/ioarules/entities/rule-groups/v1:patch')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function Edit-IOARule {
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
        $Endpoints = @('/ioarules/entities/rules/v1:patch')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function Get-IOAGroup {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/ioarules/queries/rule-groups/v1:get', '/ioarules/entities/rule-groups/v1:get')
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
function Get-IOAPlatform {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/platforms/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/ioarules/queries/platforms/v1:get', '/ioarules/entities/platforms/v1:get')
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
function Get-IOARule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rules/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/ioarules/queries/rules/v1:get', '/ioarules/entities/rules/v1:get')
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
function Get-IOASeverity {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/ioarules/queries/pattern-severities/v1:get', '/ioarules/entities/pattern-severities/v1:get')
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
function Get-IOAType {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-types/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/ioarules/queries/rule-types/v1:get', '/ioarules/entities/rule-types/v1:get')
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
function New-IOAGroup {
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
        $Endpoints = @('/ioarules/entities/rule-groups/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function New-IOARule {
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
        $Endpoints = @('/ioarules/entities/rules/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function Remove-IOAGroup {
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
        $Endpoints = @('/ioarules/entities/rule-groups/v1:delete')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Invoke-Endpoint @Param
            }
        }
    }
}
function Remove-IOARule {
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
        $Endpoints = @('/ioarules/entities/rules/v1:delete')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Invoke-Endpoint @Param
            }
        }
    }
}
function Test-IOARule {
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
        $Endpoints = @('/ioarules/entities/rules/validate/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param['Header'] = @{
                    'X-CS-USERNAME' = "api-client-id:$($Falcon.ClientId)"
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
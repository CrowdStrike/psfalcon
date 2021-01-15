function Edit-HostGroup {
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
        $Endpoints = @('/devices/entities/host-groups/v1:patch')
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
function Get-Host {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/devices-scroll/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/devices/queries/devices-scroll/v1:get', '/devices/entities/devices/v1:get',
            '/devices/queries/devices-hidden/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param['Detailed'] = $true
                }
                'Hidden' {
                    $Param.Query = $Endpoints[2]
                    $Param['Modifier'] = 'Hidden'
                }
            }
            Invoke-Request @Param
        }
    }
}
function Get-HostGroup {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-groups/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/devices/queries/host-groups/v1:get', '/devices/entities/host-groups/v1:get',
            '/devices/combined/host-groups/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                '/devices/combined/host-groups/v1:get')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Entity  = $Endpoints[1]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param.Query = $Endpoints[2]
                }
            }
            Invoke-Request @Param
        }
    }
}
function Get-HostGroupMember {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/host-group-members/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/devices/queries/host-group-members/v1:get', '/devices/combined/host-group-members/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                '/devices/combined/host-group-members/v1:get')
        }
        else {
            $Param = @{
                Command = $MyInvocation.MyCommand.Name
                Query   = $Endpoints[0]
                Dynamic = $Dynamic
            }
            switch ($PSBoundParameters.Keys) {
                'All' {
                    $Param['All'] = $true
                }
                'Detailed' {
                    $Param.Query = $Endpoints[1]
                }
            }
            Invoke-Request @Param
        }
    }
}
function Invoke-HostAction {
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
        $Endpoints = @('/devices/entities/devices-actions/v2:post')
        $Dynamic = Get-Dictionary -Endpoints $Endpoints
        @('name', 'value').foreach{
            [void] $Dynamic.Remove($_)
        }
        return $Dynamic
    }
    begin {
        $Max = if ($Dynamic.ActionName.value -match '(hide_host|unhide_host)') {
            100
        }
        else {
            500
        }
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic -Max $Max)) {
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function Invoke-HostGroupAction {
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
        $Endpoints = @('/devices/entities/host-group-actions/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $MaxHosts = 500
        $Dynamic.Id.value = @( $Dynamic.Id.Value )
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $HostIds = $Dynamic.HostIds.value
            for ($i = 0; $i -lt $HostIds.count; $i += $MaxHosts) {
                $Dynamic.HostIds.value = $HostIds[$i..($i + ($MaxHosts - 1))]
                $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
                $Param.Body.action_parameters[0] = @{
                    name  = 'filter'
                    value = ("(device_id:$(($Param.Body.action_parameters[0].value |
                        ForEach-Object { "'$_'" }) -join ','))")
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function New-HostGroup {
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
        $Endpoints = @('/devices/entities/host-groups/v1:post')
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
function Remove-HostGroup {
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
        $Endpoints = @('/devices/entities/host-groups/v1:delete')
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
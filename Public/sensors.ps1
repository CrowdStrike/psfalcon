function Get-CCID {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/ccid/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/sensors/queries/installers/ccid/v1:get')
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
function Get-Installer {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/sensors/queries/installers/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/sensors/queries/installers/v1:get', '/sensors/entities/installers/v1:get',
            '/sensors/combined/installers/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                '/sensors/combined/installers/v1:get')
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
                'Detailed' { $Param.Query = $Endpoints[2] }
            }
            Invoke-Request @Param
        }
    }
}
function Get-Stream {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/sensors/entities/datafeed/v2:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/sensors/entities/datafeed/v2:get')
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
function Receive-Installer {
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
        $Endpoints = @('/sensors/entities/download-installer/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Dynamic.Path.Value = $Falcon.GetAbsolutePath($Dynamic.Path.Value)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } elseif (Test-Path $Dynamic.Path.Value) {
            throw "'$($Dynamic.Path.Value)' already exists."
        } else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
function Update-Stream {
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
        $Endpoints = @('/sensors/entities/datafeed-actions/v1/partition:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param.Query = @( $Param.Query, "action_name=refresh_active_stream_session" )
            Invoke-Endpoint @Param
        }
    }
}

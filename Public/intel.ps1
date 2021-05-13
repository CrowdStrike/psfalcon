function Get-Actor {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/actors/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/intel/queries/actors/v1:get', '/intel/entities/actors/v1:get',
            '/intel/combined/actors/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @('/intel/combined/actors/v1:get')
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
function Get-Indicator {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/indicators/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/intel/queries/indicators/v1:get', '/intel/entities/indicators/GET/v1:post',
            '/intel/combined/indicators/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @(
                '/intel/combined/indicators/v1:get')
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
function Get-Intel {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/reports/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/intel/queries/reports/v1:get', '/intel/entities/reports/v1:get',
            '/intel/combined/reports/v1:get')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name -Exclusions @('/intel/combined/reports/v1:get')
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
function Get-Rule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/intel/queries/rules/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/intel/queries/rules/v1:get', '/intel/entities/rules/v1:get')
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
function Receive-Intel {
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
        $Endpoints = @('/intel/entities/report-files/v1:get')
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
function Receive-Rule {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/intel/entities/rules-files/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/intel/entities/rules-files/v1:get', '/intel/entities/rules-latest-files/v1:get')
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
            $Param = Get-Param -Endpoint $PSCmdlet.ParameterSetName -Dynamic $Dynamic
            $Format = if ($Param.Path -match '\.gzip$') {
                "format=gzip"
            } else {
                "format=zip"
            }
            $Param.Query = @($Param.Query, $Format)
            Invoke-Endpoint @Param
        }
    }
}
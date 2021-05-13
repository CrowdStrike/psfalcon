function Edit-IOC {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:patch')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/iocs/entities/indicators/v1:patch')
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
function Get-IOC {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/iocs/queries/indicators/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/iocs/queries/indicators/v1:get', '/iocs/entities/indicators/v1:get') # '/iocs/combined/indicators/v1:get'
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
function New-IOC {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:post')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/iocs/entities/indicators/v1:post', 'script:CreateIOCArray')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } elseif ($PSBoundParameters.Array) {
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Body = @{
                indicators = @( $PSBoundParameters.Array )
            }
            if ($Param.Body.Comment) {
                $Body['comment'] = $Param.Body.Comment
            }
            $Param.Body = $Body
            Format-Body -Param $Param
            Invoke-Endpoint @Param
        } else {
            Invoke-Request -Query $Endpoints[0] -Dynamic $Dynamic
        }
    }
}
function Remove-IOC {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/iocs/entities/indicators/v1:delete')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/iocs/entities/indicators/v1:delete')
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
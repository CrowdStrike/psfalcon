function Get-Report {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/falconx/queries/reports/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/falconx/queries/reports/v1:get', '/falconx/entities/reports/v1:get',
            '/falconx/entities/report-summaries/v1:get')
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
                'Summary' {
                    $Param.Entity = $Endpoints[2]
                    $Param['Modifier'] = 'Summary'
                }
            }
            Invoke-Request @Param
        }
    }
}
function Get-Submission {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/falconx/queries/submissions/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/falconx/queries/submissions/v1:get', '/falconx/entities/submissions/v1:get')
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
            }
            Invoke-Request @Param
        }
    }
}
function New-Submission {
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
        $Endpoints = @('/falconx/entities/submissions/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        elseif ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
            throw "Url and Sha256 cannot be combined in a submission."
        }
        else {
            if ($Dynamic.EnvironmentId.value) {
                $Dynamic.EnvironmentId.value = switch ($Dynamic.EnvironmentId.value) {
                    'Android' { 200 }
                    'Ubuntu16_x64' { 300 }
                    'Win7_x64' { 110 }
                    'Win7_x86' { 100 }
                    'Win10_x64' { 160 }
                }
            }
            $Param = Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic
            $Param['Header'] = @{
                "Accept-Encoding" = "gzip"
            }
            Format-Body -Param $Param
            Invoke-Endpoint @Param
        }
    }
}
function Receive-Artifact {
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
        $Endpoints = @('/falconx/entities/artifacts/v1:get')
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
function Remove-Report {
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
        $Endpoints = @('/falconx/entities/reports/v1:delete')
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

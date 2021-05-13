function Get-QuickScan {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = '/scanner/queries/scans/v1:get')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('/scanner/queries/scans/v1:get', '/scanner/entities/scans/v1:get')
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
function Get-QuickScanQuota {
    <#
    .SYNOPSIS
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/crowdstrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'script:QuickScanQuota')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('script:QuickScanQuota')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            try {
                Get-FalconQuickScan -Limit 1 -ErrorAction SilentlyContinue | Out-Null
                if ($Script:Meta.Quota) {
                    $Meta.Quota
                } else {
                    throw "Unable to retrieve QuickScan quota. Check client permissions."
                }
            } catch {
                Write-Error $_
            }
        }
    }
}
function New-QuickScan {
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
        $Endpoints = @('/scanner/entities/scans/v1:post')
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

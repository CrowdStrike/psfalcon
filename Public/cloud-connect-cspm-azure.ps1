function Edit-HorizonAzureAccount {
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
        $Endpoints = @('/cloud-connect-cspm-azure/entities/client-id/v1:patch')
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
function Get-HorizonAzureAccount {
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
        $Endpoints = @('/cloud-connect-cspm-azure/entities/account/v1:get')
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
function New-HorizonAzureAccount {
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
        $Endpoints = @('/cloud-connect-cspm-azure/entities/account/v1:post')
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
function Receive-HorizonAzureScript {
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
        $Endpoints = @('/cloud-connect-cspm-azure/entities/user-scripts-download/v1:get')
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
function Remove-HorizonAzureAccount {
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
        $Endpoints = @('/cloud-connect-cspm-azure/entities/account/v1:delete')
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
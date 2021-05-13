function Get-DiscoverGcpAccount {
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
        $Endpoints = @('/cloud-connect-gcp/entities/account/v1:get')
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
function New-DiscoverGcpAccount {
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
        $Endpoints = @('/cloud-connect-gcp/entities/account/v1:post')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        } else {
            foreach ($Param in (Get-Param -Endpoint $Endpoints[0] -Dynamic $Dynamic)) {
                $Param.Body.resources = ($Param.Body.resources.parent_id).foreach{
                    @{ parent_id = $_ }
                }
                Format-Body -Param $Param
                Invoke-Endpoint @Param
            }
        }
    }
}
function Receive-DiscoverGcpScript {
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
        $Endpoints = @('/cloud-connect-gcp/entities/user-scripts-download/v1:get')
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
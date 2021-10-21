function Get-FalconDiscoverAzureAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:get', Position = 2)]
        [ValidateSet('full', 'dry')]
        [string] $ScanType
    )
    begin {
        $Fields = @{
            ScanType = 'scan-type'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverGcpAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-gcp/entities/account/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{10,}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:get', Position = 2)]
        [ValidateSet('full', 'dry')]
        [string] $ScanType
    )
    begin {
        $Fields = @{
            ScanType = 'scan-type'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconDiscoverAzureAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:post', Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $SubscriptionId,

        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:post', Position = 2)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $TenantId
    )
    begin {
        $Fields = @{
            SubscriptionId = 'subscription_id'
            TenantId       = 'tenant_id'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('subscription_id', 'tenant_id')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function New-FalconDiscoverGcpAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-gcp/entities/account/v1:post')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\d{12}$')]
        [string] $ParentId
    )
    begin {
        $Fields = @{
            ParentId = 'parent_id'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('parent_id')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Receive-FalconDiscoverAzureScript {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/user-scripts-download/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^*\.sh$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
function Receive-FalconDiscoverGcpScript {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-gcp/entities/user-scripts-download/v1:get')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/user-scripts-download/v1:get',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^*\.sh$')]
        [ValidateScript({
            if (Test-Path $_) {
                throw "An item with the specified name $_ already exists."
            } else {
                $true
            }
        })]
        [string] $Path
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/octet-stream'
            }
            Format   = @{
                Outfile = 'path'
            }
        }
        Invoke-Falcon @Param
    }
}
function Update-FalconDiscoverAzureAccount {
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id')
            }
        }
        Invoke-Falcon @Param
    }
}
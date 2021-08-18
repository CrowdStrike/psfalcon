function Edit-FalconDiscoverAzureAccount {
<#
.Synopsis
Modify the Falcon Discover for Cloud Azure default client identifier
.Description
Requires 'd4c-registration:write'.
.Parameter Id
Azure client identifier
.Role
d4c-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverAzureAccount {
<#
.Synopsis
Search for Falcon Discover for Cloud Azure accounts
.Description
Requires 'd4c-registration:read'.
.Parameter Ids
Azure account identifier(s)
.Parameter ScanType
Scan type
.Role
d4c-registration:read
#>
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
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDiscoverGcpAccount {
<#
.Synopsis
Search for Falcon Discover for Cloud GCP accounts
.Description
Requires 'd4c-registration:read'.
.Parameter Ids
GCP account identifier(s)
.Parameter ScanType
Scan type
.Role
d4c-registration:read
#>
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
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconDiscoverAzureAccount {
<#
.Synopsis
Provision Falcon Discover for Cloud Azure accounts
.Description
Requires 'd4c-registration:write'.
.Parameter SubscriptionId
Azure subscription identifier
.Parameter TenantId
Azure tenant identifier
.Role
d4c-registration:write
#>
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconDiscoverGcpAccount {
<#
.Synopsis
Provision Falcon Discover for Cloud GCP accounts
.Description
Requires 'd4c-registration:write'.
.Parameter ParentId
 GCP project identifier
.Role
d4c-registration:write
#>
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconDiscoverAzureScript {
<#
.Synopsis
Download a Bash script which grants Falcon Discover for Cloud access using Azure Cloud Shell
.Description
Requires 'd4c-registration:read'.
.Role
d4c-registration:read
#>
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
    begin {
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function Receive-FalconDiscoverGcpScript {
<#
.Synopsis
 Download a Bash script which grants access using GCP CLI
 .Description
Requires 'd4c-registration:read'.
.Parameter Path
Destination path
.Role
d4c-registration:read
#>
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
    begin {
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
    }
    process {
        Invoke-Falcon @Param
    }
}
function Update-FalconDiscoverAzureAccount {
<#
.Synopsis
Update a Falcon Discover for Cloud Azure service account and client identifier
.Description
Requires 'd4c-registration:write'.
.Parameter Id
Azure account identifier
.Role
d4c-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $Id
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
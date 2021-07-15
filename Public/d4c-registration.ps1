function Get-FalconUserScripts {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their Azure environment

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconAccount {
<#
.Synopsis
Creates a new account in our system for a customer and generates a script for them to run in their cloud environment to grant us access.
.Parameter SubscriptionId

.Parameter TenantId

.Role
d4c-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:post')]
        [string] $SubscriptionId,

        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:post')]
        [string] $TenantId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Edit-FalconClientId {
<#
.Synopsis
Update an Azure service account in our system by with the user-created client_id created with the public key weve provided
.Parameter Id
XXX identifier
.Role
d4c-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/client-id/v1:patch', Mandatory = $true)]
        [ValidatePattern('^[0-9a-z-]{36}$')]
        [string] $Id
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconAccount {
<#
.Synopsis
Return information about Azure account registration
.Parameter Ids
One or more XXX identifiers
.Parameter ScanType

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:get')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-azure/entities/account/v1:get')]
        [ValidateSet('full', 'dry')]
        [ValidateLength(3, 4)]
        [string] $ScanType
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserScriptsDownload {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their Azure environment as a downloadable attachment

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconAccount {
<#
.Synopsis
Creates a new account in our system for a customer and generates a new service account for them to add access to in their GCP environment to grant us access.
.Parameter ParentId

.Role
d4c-registration:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:post', Mandatory = $true)]
        [string] $ParentId
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Get-FalconUserScripts {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their GCP environment

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
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
function Get-FalconAccount {
<#
.Synopsis
Returns information about the current status of an GCP account.
.Parameter Ids
One or more XXX identifiers
.Parameter ScanType

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:get')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/cloud-connect-gcp/entities/account/v1:get')]
        [ValidateSet('full', 'dry')]
        [ValidateLength(3, 4)]
        [string] $ScanType
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconUserScriptsDownload {
<#
.Synopsis
Return a script for customer to run in their cloud environment to grant us access to their GCP environment as a downloadable attachment

.Role
d4c-registration:read
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
    
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{
                Accept = 'application/json application/octet-stream'
            }
            Format   = @{
                Query = @('ids', 'scan-type')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
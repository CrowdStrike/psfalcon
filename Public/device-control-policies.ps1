function Edit-FalconDeviceControlPolicy {
<#
.Synopsis
Modify Device Control policies
.Parameter Array
An array of Device Control policies to modify in a single request
.Parameter Id
Device Control policy identifier
.Parameter Name
Device Control policy name
.Parameter Settings
An array of Device Control policy settings
.Parameter Description
Device Control policy description
.Role
device-control-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/device-control/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:patch', Position = 4)]
        [string] $Description
    )
    begin {
        $Fields = @{
            Array = 'resources'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('name', 'id', 'description', 'settings')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicy {
<#
.Synopsis
Search for Device Control policies
.Parameter Ids
One or more Device Control policy identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
device-control-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'ids', 'offset', 'filter', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconDeviceControlPolicyMember {
<#
.Synopsis
Search for members of Device Control policies
.Parameter Id
Device Control policy identifier
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Limit
Maximum number of results per request
.Parameter Offset
Position to begin retrieving results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
device-control-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/device-control-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/device-control-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/device-control-members/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('sort', 'offset', 'filter', 'id', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconDeviceControlPolicyAction {
<#
.Synopsis
Perform the specified action on the Device Control Policies specified in the request
.Parameter Ids
One or more XXX identifiers
.Parameter ActionName

.Parameter Name

.Parameter Value

.Role
device-control-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $ActionName,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control-actions/v1:post', Mandatory = $true)]
        [string] $Value
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body = @{
                    root              = @('ids')
                    action_parameters = @('name', 'value')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconDeviceControlPolicy {
<#
.Synopsis
Create Device Control Policies by specifying details about the policy to create
.Parameter VendorName

.Parameter Name

.Parameter Class

.Parameter Id
XXX identifier
.Parameter ProductId

.Parameter EnforcementMode

.Parameter ProductIdDecimal

.Parameter Description

.Parameter SerialNumber

.Parameter EndUserNotification

.Parameter VendorIdDecimal

.Parameter CombinedId

.Parameter CloneId

.Parameter Action

.Parameter ProductName

.Parameter VendorId

.Parameter PlatformName

.Parameter MatchMethod

.Role
device-control-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $VendorName,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $Class,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $ProductId,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $EnforcementMode,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $ProductIdDecimal,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post')]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $SerialNumber,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [ValidateSet('TRUE', 'FALSE')]
        [string] $EndUserNotification,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $VendorIdDecimal,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $CombinedId,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post')]
        [string] $CloneId,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [ValidateSet('FULL_ACCESS', 'FULL_BLOCK', 'READ_ONLY')]
        [string] $Action,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $ProductName,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $VendorId,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:post', Mandatory = $true)]
        [string] $MatchMethod
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    exceptions = @('vendor_name', 'class', 'id', 'product_id', 'product_id_decimal',
                        'serial_number', 'vendor_id_decimal', 'combined_id', 'product_name', 'vendor_id',
                        'match_method')
                    resources = @('name', 'description', 'clone_id', 'platform_name')
                    settings = @('enforcement_mode', 'end_user_notification')
                    classes = @('action')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconDeviceControlPolicy {
<#
.Synopsis
Delete a set of Device Control Policies by specifying their IDs
.Parameter Ids
One or more XXX identifiers
.Role
device-control-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control/v1:delete', Mandatory = $true)]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Set-FalconDeviceControlPrecedence {
<#
.Synopsis
Sets the precedence of Device Control Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
.Parameter PlatformName

.Parameter Ids
One or more XXX identifiers
.Role
device-control-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/device-control-precedence/v1:post', Mandatory = $true)]
        [array] $Ids
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('platform_name', 'ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
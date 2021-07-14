function Edit-FalconSensorUpdatePolicy {
<#
.Synopsis
Modify Sensor Update policies
.Parameter Array
An array of Sensor Update policies to modify in a single request
.Parameter Id
Sensor Update policy identifier
.Parameter Name
Sensor Update policy name
.Parameter Settings
An array of Sensor Update policy settings
.Parameter Description
Sensor Update policy description
.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sensor-update/v2:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:patch', Position = 4)]
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
function Get-FalconBuild {
<#
.Synopsis
Retrieve available builds for use with Sensor Update Policies
.Parameter Platform
Operating System platform
.Role
sensor-update-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/combined/sensor-update-builds/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-builds/v1:get')]
        [ValidateSet('linux', 'mac', 'windows')]
        [string] $Platform
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('platform')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconSensorUpdatePolicy {
<#
.Synopsis
Search for Sensor Update policies
.Parameter Ids
One or more Sensor Update policy identifiers
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
sensor-update-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/sensor-update/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update/v2:get')]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update/v1:get')]
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
function Get-FalconSensorUpdatePolicyMember {
<#
.Synopsis
Search for members of Sensor Update policies
.Parameter Id
Sensor Update policy identifier
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
sensor-update-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/sensor-update-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/sensor-update-members/v1:get')]
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
function Get-FalconUninstallToken {
<#
.Synopsis
Retrieve an uninstall or maintenance token
.Parameter DeviceId
Host identifier
.Parameter AuditMessage
Audit log comment
.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^(\w{32}|MAINTENANCE)$')]
        [string] $DeviceId,

        [Parameter(ParameterSetName = '/policy/combined/reveal-uninstall-token/v1:post', Position = 2)]
        [string] $AuditMessage
    )
    begin {
        $Fields = @{
            DeviceId     = 'device_id'
            AuditMessage = 'audit_message'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('audit_message', 'device_id')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Invoke-FalconSensorUpdatePolicyAction {
<#
.Synopsis
Perform the specified action on the Sensor Update Policies specified in the request
.Parameter Ids
One or more XXX identifiers
.Parameter ActionName

.Parameter Name

.Parameter Value

.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $ActionName,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-actions/v1:post', Mandatory = $true)]
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
                    root = @('ids')
                    action_parameters = @('name', 'value')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconSensorUpdatePolicy {
<#
.Synopsis
Create Sensor Update Policies by specifying details about the policy to create

Create Sensor Update Policies by specifying details about the policy to create with additional support for uninstall protection
.Parameter Description

.Parameter UninstallProtection

.Parameter PlatformName

.Parameter Name

.Parameter Build

.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:post')]
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post')]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post')]
        [ValidateSet('ENABLED', 'DISABLED', 'MAINTENANCE_MODE', 'IGNORE', 'UNKNOWN')]
        [string] $UninstallProtection,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:post', Mandatory = $true)]
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:post', Mandatory = $true)]
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:post')]
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v2:post')]
        [string] $Build
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{}
            Format   = @{
                Body = @{
                    resources = @('description', 'platform_name', 'name')
                    settings = @('uninstall_protection', 'build')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconSensorUpdatePolicy {
<#
.Synopsis
Delete a set of Sensor Update Policies by specifying their IDs
.Parameter Ids
One or more XXX identifiers
.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update/v1:delete', Mandatory = $true)]
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
function Set-FalconSensorUpdatePrecedence {
<#
.Synopsis
Sets the precedence of Sensor Update Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence
.Parameter PlatformName

.Parameter Ids
One or more XXX identifiers
.Role
sensor-update-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sensor-update-precedence/v1:post', Mandatory = $true)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/sensor-update-precedence/v1:post', Mandatory = $true)]
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
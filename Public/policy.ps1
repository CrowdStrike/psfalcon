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
function Edit-FalconFirewallPolicy {
<#
.Synopsis
Modify Firewall Management policies
.Parameter Array
An array of Firewall Management policies to modify in a single request
.Parameter Id
Firewall Management policy identifier
.Parameter Name
Firewall Management policy name
.Parameter Description
Firewall Management policy description
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Position = 3)]
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
                    resources = @('name', 'id', 'description')
                    root      = @('resources')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconIoaExclusion {
<#
.Synopsis
Modify Indicator of Attack exclusions
.Parameter Id
Indicator of Attack exclusion identifier
.Parameter Name
Indicator of Attack exclusion name
.Parameter ClRegex
Command line RegEx
.Parameter IfnRegex
Image Filename RegEx
.Parameter GroupIds
One or more Host Group identifiers, or 'all' for all Host Groups
.Parameter Description
Indicator of Attack exclusion description
.Parameter Comment
Audit log comment
.Role
self-service-ioa-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ioa-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 3)]
        [string] $ClRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 4)]
        [string] $IfnRegex,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 5)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:patch', Position = 7)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            ClRegex  = 'cl_regex'
            GroupIds = 'groups'
            IfnRegex = 'ifn_regex'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('cl_regex', 'ifn_regex', 'groups', 'name', 'id', 'description', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconMlExclusion {
<#
.Synopsis
Modify Machine Learning exclusions
.Parameter Id
Machine Learning exclusion identifier
.Parameter Value
RegEx pattern value
.Parameter GroupIds
One or more Host Group identifiers, or 'all' for all Host Groups
.Parameter Comment
Audit log comment
.Role
ml-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/ml-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:patch', Position = 4)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            GroupIds = 'groups'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'id', 'value', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconPreventionPolicy {
<#
.Synopsis
Modify Prevention policies
.Parameter Array
An array of Prevention policies to modify in a single request
.Parameter Id
Prevention policy identifier
.Parameter Name
Prevention policy name
.Parameter Settings
An array of Prevention policy settings
.Parameter Description
Prevention policy description
.Role
prevention-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/prevention/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:patch', Position = 4)]
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
function Edit-FalconResponsePolicy {
<#
.Synopsis
Modify Response policies
.Parameter Array
An array of Response policies to modify in a single request
.Parameter Id
Response policy identifier
.Parameter Name
Response policy name
.Parameter Settings
An array of Response policy settings
.Parameter Description
Response policy description
.Role
response-policies:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/response/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'create_array', Mandatory = $true, Position = 1)]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/response/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/response/v1:patch', Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/response/v1:patch', Position = 3)]
        [array] $Settings,

        [Parameter(ParameterSetName = '/policy/entities/response/v1:patch', Position = 4)]
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
function Edit-FalconSvExclusion {
<#
.Synopsis
Modify Sensor Visibility exclusions
.Parameter Id
Sensor Visibility exclusion identifier
.Parameter Value
RegEx pattern value
.Parameter GroupIds
One or more Host Group identifiers, or 'all' for all Host Groups
.Parameter Comment
Audit log comment
.Role
sensor-visibility-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/sv-exclusions/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:patch', Position = 2)]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:patch', Position = 3)]
        [ValidatePattern('^(\w{32}|all)$')]
        [array] $GroupIds,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:patch', Position = 4)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            GroupIds = 'groups'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'id', 'value', 'comment')
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
function Get-FalconFirewallPolicy {
<#
.Synopsis
Search for Firewall Management policies
.Parameter Ids
One or more Firewall Management policy identifiers
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
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/firewall/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/firewall/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/firewall/v1:get')]
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
function Get-FalconFirewallPolicyMember {
<#
.Synopsis
Search for members of Firewall Management policies
.Parameter Id
Firewall Management policy identifier
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
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/firewall-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get')]
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
function Get-FalconIoaExclusion {
<#
.Synopsis
Search for Indicator of Attack exclusions
.Parameter Ids
One or more Indicator of Attack exclusion identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
self-service-ioa-exclusions:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'name.asc', 'name.desc', 'pattern_id.asc', 'pattern_id.desc', 'pattern_name.asc',
            'pattern_name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/ioa-exclusions/v1:get')]
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
function Get-FalconMlExclusion {
<#
.Synopsis
Search for Machine Learning exclusions
.Parameter Ids
One or more Machine Learning exclusion identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
ml-exclusions:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'value.asc', 'value.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/ml-exclusions/v1:get')]
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
function Get-FalconPreventionPolicy {
<#
.Synopsis
Search for Prevention policies
.Parameter Ids
One or more Prevention policy identifiers
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
prevention-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/prevention/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/prevention/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/prevention/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/prevention/v1:get')]
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
function Get-FalconPreventionPolicyMember {
<#
.Synopsis
Search for members of Prevention policies
.Parameter Id
Prevention policy identifier
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
prevention-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/prevention-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/prevention-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/prevention-members/v1:get')]
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
function Get-FalconResponsePolicy {
<#
.Synopsis
Search for Response policies
.Parameter Ids
One or more Response policy identifiers
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
response-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/response/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/response/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/queries/response/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/queries/response/v1:get', Position = 2)]
        [ValidateSet('created_by.asc', 'created_by.desc', 'created_timestamp.asc', 'created_timestamp.desc',
            'enabled.asc', 'enabled.desc', 'modified_by.asc', 'modified_by.desc', 'modified_timestamp.asc',
            'modified_timestamp.desc', 'name.asc', 'name.desc', 'platform_name.asc', 'platform_name.desc',
            'precedence.asc', 'precedence.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/queries/response/v1:get', Position = 3)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/queries/response/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/response/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/response/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/response/v1:get')]
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
function Get-FalconResponsePolicyMember {
<#
.Synopsis
Search for members of Response policies
.Parameter Id
Response policy identifier
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
response-policies:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/response-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Position = 2)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Position = 4)]
        [ValidateRange(1, 5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/combined/response-members/v1:get')]
        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/response-members/v1:get')]
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
function Get-FalconSvExclusion {
<#
.Synopsis
Search for Sensor Visibility exclusions
.Parameter Ids
One or more Sensor Visibility exclusion identifiers
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Sort
Property and direction to sort results
.Parameter Offset
Position to begin retrieving results
.Parameter Limit
Maximum number of results per request
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
ml-exclusions:read
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/sv-exclusions/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get', Position = 2)]
        [ValidateSet('applied_globally.asc', 'applied_globally.desc', 'created_by.asc', 'created_by.desc',
            'created_on.asc', 'created_on.desc', 'last_modified.asc', 'last_modified.desc', 'modified_by.asc',
            'modified_by.desc', 'value.asc', 'value.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get', Position = 3)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/policy/queries/sv-exclusions/v1:get')]
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
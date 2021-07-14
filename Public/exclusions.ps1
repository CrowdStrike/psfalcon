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
function New-FalconMlExclusion {
<#
.Synopsis
Create the ML exclusions
.Parameter Groups

.Parameter Value

.Parameter Comment
Audit log comment
.Role
ml-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post')]
        [array] $Groups,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post')]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:post')]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'value', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconSvExclusion {
<#
.Synopsis
Create the sensor visibility exclusions
.Parameter Groups

.Parameter Value

.Parameter Comment
Audit log comment
.Role
sensor-visibility-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:post')]
        [array] $Groups,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:post')]
        [string] $Value,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:post')]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('groups', 'value', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoaExclusion {
<#
.Synopsis
Delete the IOA exclusions by id
.Parameter Ids
One or more XXX identifiers
.Parameter Comment
Audit log comment
.Role
self-service-ioa-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/ioa-exclusions/v1:delete')]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconMlExclusion {
<#
.Synopsis
Delete the ML exclusions by id
.Parameter Ids
One or more XXX identifiers
.Parameter Comment
Audit log comment
.Role
ml-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:delete', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/ml-exclusions/v1:delete')]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconSvExclusion {
<#
.Synopsis
Delete the sensor visibility exclusions by id
.Parameter Ids
One or more XXX identifiers
.Parameter Comment
Audit log comment
.Role
sensor-visibility-exclusions:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:delete', Mandatory = $true)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/policy/entities/sv-exclusions/v1:delete')]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{Query = @('ids', 'comment')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
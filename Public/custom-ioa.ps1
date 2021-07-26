function Edit-FalconIoaGroup {
<#
.Synopsis
Modify a Custom IOA rule group
.Parameter Id
Custom IOA rule group identifier
.Parameter Name
Custom IOA rule group name
.Parameter Enabled
Custom IOA rule group status
.Parameter RulegroupVersion
Custom IOA rule group version
.Parameter Description
Custom IOA rule group description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 3)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 4)]
        [int64] $RulegroupVersion,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 5)]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:patch', Mandatory = $true, Position = 6)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            RuleGroupVersion = 'rulegroup_version'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('description', 'rulegroup_version', 'name', 'enabled', 'id', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconIoaRule {
<#
.Synopsis
Modify custom IOA rules within an IOA rule group
.Parameter RulegroupId
Custom IOA rule group identifier
.Parameter RulegroupVersion
Custom IOA rule group version
.Parameter RuleUpdates
An array of custom IOA rule properties
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RulegroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Mandatory = $true, Position = 2)]
        [int64] $RulegroupVersion,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Position = 3)]
        [array] $RuleUpdates,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:patch', Position = 4)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            RuleGroupId      = 'rulegroup_id'
            RuleGroupVersion = 'rulegroup_version'
            RuleUpdates      = 'rule_updates'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('rulegroup_id', 'comment', 'rule_updates')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaGroup {
<#
.Synopsis
Search for Custom IOA rule groups
.Parameter Ids
Custom IOA rule group identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
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
custom-ioa:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 3)]
        [ValidateSet('created_by', 'created_on', 'description', 'enabled', 'modified_by', 'modified_on', 'name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups-full/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-groups/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaPlatform {
<#
.Synopsis
List Custom IOA platforms
.Parameter Ids
Custom IOA platform(s)
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
custom-ioa:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/platforms/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/platforms/v1:get', Mandatory = $true, Position = 1)]
        [ValidateSet('windows', 'mac', 'linux')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get', Position = 2)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get', Position = 3)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/platforms/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaRule { 
<#
.Synopsis
Search for Custom IOA rules
.Parameter Ids
Custom IOA rule identifier(s)
.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Query
Perform a generic substring search across available fields
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
custom-ioa:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/GET/v1:post', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 3)]
        [ValidateSet('rules.created_by', 'rules.created_on', 'rules.current_version.action_label',
            'rules.current_version.description', 'rules.current_version.modified_by',
            'rules.current_version.modified_on', 'rules.current_version.name',
            'rules.current_version.pattern_severity', 'rules.enabled', 'rules.ruletype_name')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 4)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rules/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'sort', 'q', 'offset', 'filter')
                Body  = @{
                    root = @('ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaSeverity {
<#
.Synopsis
List Custom IOA severity levels
.Parameter Ids
Custom IOA severities
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
custom-ioa:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/pattern-severities/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^(critical|high|medium|low|informational)$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get', Position = 1)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get', Position = 2)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/pattern-severities/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconIoaType {
<#
.Synopsis
List Custom IOA types
.Parameter Ids
Custom IOA types
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
custom-ioa:read
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/queries/rule-types/v1:get')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-types/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{1,2}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get', Position = 2)]
        [ValidateRange(1,500)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get', Position = 3)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/ioarules/queries/rule-types/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoaGroup {
<#
.Synopsis
Create a Custom IOA rule group
.Parameter Platform
Operating System platform
.Parameter Name
Custom IOA rule group name
.Parameter Description
Custom IOA rule group description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('windows', 'mac', 'linux')]
        [string] $Platform,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:post', Position = 4)]
        [string] $Comment
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('description', 'platform', 'name', 'comment')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconIoaRule {
<#
.Synopsis
Create a Custom IOA rule within a rule group
.Parameter RulegroupId
Custom IOA rule group identifier
.Parameter Name
Custom IOA rule name
.Parameter PatternSeverity
Custom IOA rule severity
.Parameter RuletypeId
Custom IOA rule type
.Parameter DispositionId
Disposition identifier (10: Monitor, 20: Detect, 30: Block)
.Parameter FieldValues
An array of Custom IOA rule properties
.Parameter Description
Custom IOA rule description
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RulegroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 3)]
        [ValidateSet('critical', 'high', 'medium', 'low', 'informational')]
        [string] $PatternSeverity,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 4)]
        [ValidateSet(1, 2, 5, 6, 9, 10, 11, 12)]
        [string] $RuletypeId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 5)]
        [ValidateSet(10, 20, 30)]
        [int32] $DispositionId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post', Mandatory = $true, Position = 6)]
        [array] $FieldValues,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post')]
        [string] $Description,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:post')]
        [string] $Comment
    )
    begin {
        $Fields = @{
            DispositionId   = 'disposition_id'
            FieldValues     = 'field_values'
            PatternSeverity = 'pattern_severity'
            RulegroupId     = 'rulegroup_id'
            RuletypeId      = 'ruletype_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('rulegroup_id', 'disposition_id', 'comment', 'description', 'pattern_severity',
                        'ruletype_id', 'field_values')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconIoaGroup {
<#
.Synopsis
Delete Custom IOA rule groups
.Parameter Ids
Custom IOA rule group identifier(s)
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rule-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/entities/rule-groups/v1:delete', Position = 2)]
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
function Remove-FalconIoaRule {
<#
.Synopsis
Remove Custom IOA rules from rule groups
.Parameter RuleGroupId
Custom IOA rule group identifier
.Parameter Ids
Custom IOA rule identifier(s)
.Parameter Comment
Audit log comment
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $RuleGroupId,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete', Mandatory = $true, Position = 2)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/ioarules/entities/rules/v1:delete')]
        [string] $Comment
    )
    begin {
        $Fields = @{
            RuleGroupId = 'rule_group_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'rule_group_id', 'comment')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Test-FalconIoaRule {
<#
.Synopsis
Validate fields and patterns of a Custom IOA rule
.Parameter Fields
An array of Custom IOA Rule properties
.Role
custom-ioa:write
#>
    [CmdletBinding(DefaultParameterSetName = '/ioarules/entities/rules/validate/v1:post')]
    param(
        [Parameter(ParameterSetName = '/ioarules/entities/rules/validate/v1:post', Mandatory = $true,
            Position = 1)]
        [array] $Fields
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('fields')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
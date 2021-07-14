function Edit-FalconFirewallGroup {
<#
.Synopsis
Modify Firewall Management rule groups
.Parameter Id
Firewall Management rule group identifier
.Parameter DiffOperations
An array of hashtables containing rule or rule group changes
.Parameter RuleIds
Firewall Management rule identifiers
.Parameter RuleVersions
Rule version values
.Parameter Tracking
Tracking value
.Parameter Comment
Audit log comment
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/rule-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Mandatory = $true, Position = 1)]
        [string] $Id,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Mandatory = $true, Position = 2)]
        [array] $DiffOperations,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Mandatory = $true, Position = 3)]
        [array] $RuleIds,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 4)]
        [array] $RuleVersions,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 5)]
        [string] $Tracking,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 6)]
        [string] $Comment
    )
    begin {
        $PSBoundParameters.Add('diff_type', 'application/json-patch+json')
        $Fields = @{
            DiffOperations = 'diff_operations'
            RuleIds        = 'rule_ids'
            RuleVersions   = 'rule_versions'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Query = @('comment')
                Body  = @{
                    root = @('rule_ids', 'tracking', 'id', 'diff_type', 'rule_versions', 'diff_operations')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Edit-FalconFirewallSetting {
<#
.Synopsis
Modify Firewall Management policy settings
.Parameter PolicyId
Firewall Management policy identifier
.Parameter PlatformId
Operating System platform identifier
.Parameter Enforce
Enforce this policy on target Host Groups
.Parameter RuleGroupIds
One or more Firewall Management rule group identifiers
.Parameter IsDefaultPolicy
Set as default policy
.Parameter DefaultInbound
Default action for inbound traffic
.Parameter DefaultOutbound
Default action for outbound traffic
.Parameter MonitorMode
Override all block rules in this policy and turn on monitoring
.Parameter Tracking
Tracking value
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/policies/v1:put')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Mandatory = $true, Position = 2)]
        [ValidateSet('0')]
        [string] $PlatformId,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 3)]
        [boolean] $Enforce,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 4)]
        [array] $RuleGroupIds,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 5)]
        [boolean] $IsDefaultPolicy,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 6)]
        [ValidateSet('ALLOW', 'DENY')]
        [string] $DefaultInbound,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 7)]
        [ValidateSet('ALLOW', 'DENY')]
        [string] $DefaultOutbound,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 8)]
        [boolean] $MonitorMode,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 9)]
        [string] $Tracking
    )
    begin {
        $Fields = @{
            DefaultInbound  = 'default_inbound'
            DefaultOutbound = 'default_outbound'
            IsDefaultPolicy = 'is_default_policy'
            MonitorMode     = 'test_mode'
            PolicyId        = 'policy_id'
            PlatformId      = 'platform_id'
            RuleGroupIds    = 'rule_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Headers  = @{
                ContentType = 'application/json'
            }
            Format   = @{
                Body = @{
                    root = @('platform_id', 'tracking', 'policy_id', 'test_mode', 'is_default_policy', 'enforce',
                        'default_outbound', 'default_inbound', 'rule_group_ids')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallEvent {
<#
.Synopsis
Search for Firewall Management events
.Parameter Ids
One or more Firewall Management event identifiers
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
.Parameter After
Pagination token to retrieve the next set of results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/events/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/events/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 4)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get', Position = 6)]
        [string] $After,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/fwmgr/queries/events/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Headers  = @{}
            Format   = @{Query = @('limit', 'ids', 'sort', 'q', 'offset', 'after', 'filter')}
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallField {
<#
.Synopsis
Search for Firewall Management fields
.Parameter Ids
One or more Firewall Management field identifiers
.Parameter PlatformId
Operating System platform
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
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/firewall-fields/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/firewall-fields/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get', Position = 1)]
        [string] $PlatformId,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get', Position = 2)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get', Position = 3)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/fwmgr/queries/firewall-fields/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            PlatformId = 'platform_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('ids', 'offset', 'limit', 'platform_id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallGroup {
<#
.Synopsis
Search for Firewall Management rule groups
.Parameter Ids
One or more Firewall Management rule group identifiers
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
.Parameter After
Pagination token to retrieve the next set of results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/rule-groups/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 4)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get', Position = 6)]
        [string] $After,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/fwmgr/queries/rule-groups/v1:get')]
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
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'after', 'filter')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallPlatform {
<#
.Synopsis
Search for Firewall Management platforms
.Parameter Ids
One or more Firewall Management platform identifiers
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
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/platforms/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/platforms/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get', Position = 1)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get', Position = 2)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get')]
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
function Get-FalconFirewallRule {
<#
.Synopsis
Search for Firewall Management rules
.Parameter Ids
One or more Firewall Management rule identifiers
.Parameter PolicyId
Return rules in precedence order for a specific Firewall Management policy identifier
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
.Parameter After
Pagination token to retrieve the next set of results
.Parameter Detailed
Retrieve detailed information
.Parameter All
Repeat requests until all available results are retrieved
.Parameter Total
Display total result count instead of results
.Role
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/rules/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rules/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Mandatory = $true, Position = 1)]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 1)]
        [string] $Filter,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 4)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get', Position = 6)]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 5)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get', Position = 6)]
        [string] $After,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName = '/fwmgr/queries/rules/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            PolicyId = 'id'
            Query    = 'q'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('limit', 'ids', 'sort', 'q', 'offset', 'after', 'filter', 'id')
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Get-FalconFirewallSetting {
<#
.Synopsis
Retrieve detailed Firewall Management policy information
.Parameter Ids
One or more Firewall Management policy identifiers
.Role
firewall-management:read
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/policies/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
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
function New-FalconFirewallGroup {
<#
.Synopsis
Create new rule group on a platform for a customer with a name and description, and return the ID
.Parameter From

.Parameter Action

.Parameter PeriodMs

.Parameter Value

.Parameter Enabled

.Parameter Name

.Parameter IcmpType

.Parameter Library

.Parameter Address

.Parameter Label

.Parameter Start

.Parameter To

.Parameter TimeZone

.Parameter IcmpCode

.Parameter Netmask

.Parameter Comment
Audit log comment
.Parameter Size

.Parameter AddressFamily

.Parameter Missing

.Parameter MinDocCount

.Parameter Direction

.Parameter PlatformIds

.Parameter End

.Parameter Interval

.Parameter CloneId

.Parameter Description

.Parameter Filter
Falcon Query Language expression to limit results
.Parameter Log

.Parameter FinalValue

.Parameter TempId

.Parameter Protocol

.Parameter Q
Perform a generic substring search across available fields
.Parameter XCSUSERNAME

.Parameter Field

.Parameter Type

.Parameter Sort
Property and direction to sort results
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Action,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $PeriodMs,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $Value,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Name,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $IcmpType,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $Library,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Address,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $Label,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [integer] $Start,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $IcmpCode,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [byte] $Netmask,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $Comment,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $AddressFamily,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Direction,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [array] $PlatformIds,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [integer] $End,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $CloneId,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Description,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [boolean] $Log,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
        [string] $FinalValue,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $TempId,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Protocol,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $XCSUSERNAME,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true)]
        [string] $Type
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
                Query = @('library', 'comment', 'clone_id')
                Body = @{
                    root = @('enabled', 'name', 'time_zone', 'size', 'missing', 'min_doc_count', 'interval',
                        'description', 'filter', 'q', 'field', 'type', 'sort')
                    local_port = @('start', 'end')
                    rules = @('action', 'address_family', 'direction', 'platform_ids', 'log', 'temp_id',
                        'protocol')
                    date_ranges = @('from', 'to')
                    local_address = @('address', 'netmask')
                    icmp = @('icmp_type', 'icmp_code')
                    fields = @('value', 'label', 'final_value')
                    monitor = @('period_ms')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function Remove-FalconFirewallGroup {
<#
.Synopsis
Remove Firewall Management rule groups
.Parameter Ids
One or more Firewall Management rule group identifiers
.Parameter Comment
Audit log comment
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/rule-groups/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:delete', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:delete', Position = 2)]
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
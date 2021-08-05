function Edit-FalconFirewallGroup {
<#
.Synopsis
Modify Firewall Management rule groups
.Parameter Id
Firewall Management rule group identifier
.Parameter DiffOperations
An array of hashtables containing rule or rule group changes
.Parameter RuleIds
Firewall Management rule identifier(s)
.Parameter RuleVersions
Rule version value(s)
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
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Item in $_) {
                if ($Item.PSObject.Properties.Name -contains 'id') {
                    $true
                } else {
                    throw "'id' is required for each policy."
                }
            }
        })]
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
            Endpoint = '/policy/entities/firewall/v1:patch'
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
Firewall Management rule group identifier(s)
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
        [ValidatePattern('^\w{32}$')]
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
Firewall Management event identifier(s)
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
function Get-FalconFirewallField {
<#
.Synopsis
Search for Firewall Management fields
.Parameter Ids
Firewall Management field identifier(s)
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
Firewall Management rule group identifier(s)
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
Firewall Management platform identifier(s)
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
function Get-FalconFirewallPolicy {
<#
.Synopsis
Search for Firewall Management policies
.Parameter Ids
Firewall Management policy identifier(s)
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
Search for Firewall Management policy members
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
function Get-FalconFirewallRule {
<#
.Synopsis
Search for Firewall Management rules
.Parameter Ids
Firewall Management rule identifier(s)
.Parameter PolicyId
Return rules in precedence order for a specific Firewall Management policy
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
        [ValidatePattern('^\w{32}$')]
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
List general settings for a Firewall Management policy
.Parameter Ids
Firewall Management policy identifier(s)
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
function Invoke-FalconFirewallPolicyAction {
<#
.Synopsis
Perform actions on Firewall Management policies
.Parameter Name
Action to perform
.Parameter Id
Firewall Management policy identifier
.Parameter GroupId
Host group identifier
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
        [string] $GroupId
    )
    begin {
        $Fields = @{
            name = 'action_name'
        }
        $PSBoundParameters.Add('Ids', @( $PSBoundParameters.Id ))
        [void] $PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $Action = @{
                name  = 'group_id'
                value = @( $PSBoundParameters.GroupId )
            }
            $PSBoundParameters.Add('action_parameters', $Action)
            [void] $PSBoundParameters.Remove('GroupId')
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body = @{
                    root = @('ids', 'action_parameters')
                }
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
Create Firewall Management rule groups
.Parameter Name
Firewall Management rule group name
.Parameter Enabled
Firewall Management rule group status
.Parameter CloneId
Clone an existing Firewall Management rule group
.Parameter Library
Clone default Firewall Management rules
.Parameter Rules
An array of Firewall Management rule properties
.Parameter Description
Firewall Management rule group description
.Parameter Comment
Audit log comment
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true, Position = 2)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 3)]
        [string] $CloneId,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 4)]
        [string] $Library,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 5)]
        [array] $Rules,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 6)]
        [string] $Description,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 7)]
        [string] $Comment
    )
    begin {
        $Fields = @{
            CloneId = 'clone_id'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('library', 'comment', 'clone_id')
                Body = @{
                    root = @('enabled', 'name', 'rules', 'description')
                }
            }
        }
    }
    process {
        Invoke-Falcon @Param
    }
}
function New-FalconFirewallPolicy {
<#
.Synopsis
Create Firewall Management policies
.Parameter Array
An array of Firewall Management policies to create in a single request
.Parameter PlatformName
Operating System platform
.Parameter Name
Firewall Management policy name
.Parameter Description
Firewall Management policy description
.Parameter CloneId
Clone an existing Firewall Management policy
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Item in $_) {
                foreach ($Property in @('platform_name', 'name')) {
                    if ($Item.PSObject.Properties.Name -contains $Property) {
                        $true
                    } else {
                        throw "'$Property' is required for each policy."
                    }
                }
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Mandatory = $true, Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Position = 3)]
        [string] $Description,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:post', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [string] $CloneId
    )
    begin {
        $Fields = @{
            Array        = 'resources'
            CloneId      = 'clone_id'
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/firewall/v1:post'
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    resources = @('description', 'clone_id', 'platform_name', 'name')
                    root      = @('resources')
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
Firewall Management rule group identifier(s)
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
function Remove-FalconFirewallPolicy {
<#
.Synopsis
Delete Firewall Management policies
.Parameter Ids
Firewall Management policy identifier(s)
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:delete')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:delete', Mandatory = $true, Position = 1)]
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
function Set-FalconFirewallPrecedence {
<#
.Synopsis
Set Firewall Management policy precedence
.Parameter PlatformName
Operating System platform
.Parameter Ids
All Firewall Management policy identifiers in desired precedence order
.Role
firewall-management:write
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall-precedence/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('Windows', 'Mac', 'Linux')]
        [string] $PlatformName,

        [Parameter(ParameterSetName = '/policy/entities/firewall-precedence/v1:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    begin {
        $Fields = @{
            PlatformName = 'platform_name'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
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
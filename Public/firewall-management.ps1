function Edit-FalconFirewallGroup {
<#
.Synopsis
Modify Firewall rule groups
.Description
Requires 'firewall-management:write'.

All fields (plus 'rulegroup_version') are required when making a Firewall rule group change. PSFalcon
adds missing values automatically using data from your existing rule group.

'DiffOperations' array objects must contain 'op', 'path' and 'value' properties. Accepted 'op' values are 'add',
'remove' and 'replace'.

When adding a rule to a rule group, the required rule fields must be included along with a 'temp_id' (in both the
rule properties and in precedence order within 'rule_ids') to establish proper placement of the rule within the
rule group. Simlarly, the value 'null' must be placed within 'rule_versions' in precedence order.

PSFalcon will accept 'temp_id' values between 1 and 500, allowing batches of up to 500 rules per request.
.Parameter Id
Firewall rule group identifier
.Parameter DiffOperations
An array of hashtables containing rule or rule group changes
.Parameter RuleIds
Firewall rule identifier(s) within the existing rule group
.Parameter RuleVersions
Rule version value(s), using 'null' for the value when adding new rules
.Parameter Comment
Audit log comment
.Role
firewall-management:write
.Example
PS>$DiffOperations = @(@{ op = 'replace'; path = '/enabled'; value = $true })
PS>Edit-FalconFirewallGroup -Id <id> -DiffOperations $DiffOperations

Use 'DiffOperations' to 'enable' the Custom IOA rule group <id>.
.Example
PS>$DiffOperations = @(@{ op = 'add'; path = '/rules/0'; value = @{ temp_id = '1'; name = 'First rule in a group';
    description = 'Example'; platform_ids = @('0'); enabled = $false; action = 'ALLOW'; direction = 'IN';
    address_family = 'NONE'; protocol = '6'; fields = @(@{ name = 'network_location'; type = 'set';
    values = @( 'ANY' )}); local_address = @(@{ address = '*'; netmask = 0 }); remote_address = @(@{
    address = '*'; netmask = 0 })}})
PS>$Group = Get-FalconFirewallGroup -Ids <id>
PS>$Rules = Get-FalconFirewallRule -Ids $Group.rule_ids
PS>$RuleIds = @('1') + $Group.rule_ids
PS>$RuleVersions = @('null') + $Rules.version
PS>Edit-FalconFirewallGroup -Id $Group.id -DiffOperations $DiffOperations -RuleIds $RuleIds
    -RuleVersions $RuleVersions

Set '$DiffOperations' to 'add' the rule 'First rule in a group' to the top of the existing rules, gather and save
the existing rule group to '$Group', then use '$Group' to collect and save information about the existing rules
in that group to '$Rules'. Create '$RuleIds' with the 'temp_id' value (as a string) and add the existing
'rule_ids', then create '$RuleVersions' with 'null' for the rule being created, followed by the 'rule_versions' for
each of the existing rules. Finally, request the change to the rule group to add the rule using related variables.
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/rule-groups/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Mandatory = $true, Position = 2)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconFirewallGroup'
                    Endpoint = '/fwmgr/entities/rule-groups/v1:patch'
                    Required = @('op', 'path', 'value')
                }
                Confirm-Parameter @Param
                if ($Object.op -notmatch '^(add|remove|replace)$') {
                    $ObjectString = ConvertTo-Json -InputObject $Object -Compress
                    throw "'$($Object.op)' is not a valid 'op' value. $ObjectString"
                }
            }
        })]
        [array] $DiffOperations,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 3)]
        [ValidatePattern('^(([0-9]|[1-9][0-9]|[1-4][0-9][0-9]|500)|\w{32})$')]
        [array] $RuleIds,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 4)]
        [ValidatePattern('^(null|\d+)$')]
        [array] $RuleVersions,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:patch', Position = 6)]
        [string] $Comment
    )
    begin {
        $PSBoundParameters.Add('diff_type', 'application/json-patch+json')
        $Fields = @{
            DiffOperations   = 'diff_operations'
            RuleIds          = 'rule_ids'
            RuleVersions     = 'rule_versions'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('comment')
                Body  = @{
                    root = @('rule_ids', 'tracking', 'id', 'diff_type', 'rule_versions', 'diff_operations',
                        'rulegroup_version')
                }
            }
        }
        ($Param.Format.Body.root | Where-Object { $_ -notmatch '^(diff_operations|id)$' }).foreach{
            # When not provided, add required fields using existing rule group
            if (!$Param.Inputs.$_) {
                if (!$Group) {
                    $Group = Get-FalconFirewallGroup -Ids $Param.Inputs.id -ErrorAction 'SilentlyContinue'
                    $RuleVersions = (Get-FalconFirewallRule -Ids $Group.rule_ids).version
                }
                if ($Group) {
                    $Value = if ($_ -eq 'rulegroup_version') {
                        if ($Group.version) {
                            $Group.version
                        } else {
                            0
                        }
                    } elseif ($_ -eq 'rule_versions') {
                        $RuleVersions
                    } else {
                        $Group.$_
                    }
                    $PSBoundParameters.Add($_,$Value)
                }
            }
        }
    }
    process {
        if ($PSBoundParameters.Tracking) {
            Invoke-Falcon @Param
        } else {
            throw "Unable to obtain 'tracking' value from rule group '$($PSBoundParameters.Id)'."
        }
    }
}
function Edit-FalconFirewallPolicy {
<#
.Synopsis
Modify Firewall policies
.Description
Requires 'firewall-management:write'.
.Parameter Array
An array of Firewall policies to modify in a single request
.Parameter Id
Firewall policy identifier
.Parameter Name
Firewall policy name
.Parameter Description
Firewall policy description
.Role
firewall-management:write
.Example
PS>Edit-FalconFirewallPolicy -Id <id> -Name 'Name Changed'

Change the name of Firewall policy <id> to 'Name Changed'.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:patch')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'Edit-FalconFirewallPolicy'
                    Endpoint = '/policy/entities/firewall/v1:patch'
                    Required = @('id')
                    Pattern  = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [array] $Array,

        [Parameter(ParameterSetName = '/policy/entities/firewall/v1:patch', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
Modify Firewall policy settings
.Description
Requires 'firewall-management:write'.

All fields are required to modify Firewall policy settings. PSFalcon adds missing values automatically
using data from your existing policy.

If adding or removing rule groups, all rule groups must be supplied in precedence order.
.Parameter PolicyId
Firewall policy identifier
.Parameter PlatformId
Operating System platform identifier
.Parameter Enforce
Enforce this policy on target Host Groups
.Parameter RuleGroupIds
Firewall rule group identifier(s)
.Parameter DefaultInbound
Default action for inbound traffic
.Parameter DefaultOutbound
Default action for outbound traffic
.Parameter MonitorMode
Override all block rules in this policy and turn on monitoring
.Role
firewall-management:write
.Example
PS>Edit-FalconFirewallSetting -PolicyId <id> -Enforce $true -DefaultInbound DENY -DefaultOutbound ALLOW

Modify Firewall policy <id> to enable 'enforce', set 'default_inbound' to 'DENY' and 'default_outbound' to 'ALLOW'.
.Example
PS>$Settings = Get-FalconFirewallSetting -Ids <id>
PS>Edit-FalconFirewallSetting -PolicyId $Settings.id -RuleGroupIds ($Settings.rule_group_ids + <rule_group_id>)

Modify Firewall policy <id> to add <rule_group_id> at the end of the existing assigned rule groups.
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/policies/v1:put')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [string] $PolicyId,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 2)]
        [ValidateSet('0')]
        [string] $PlatformId,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 3)]
        [boolean] $Enforce,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 4)]
        [ValidatePattern('^\w{32}$')]
        [array] $RuleGroupIds,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 6)]
        [ValidateSet('ALLOW', 'DENY')]
        [string] $DefaultInbound,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 7)]
        [ValidateSet('ALLOW', 'DENY')]
        [string] $DefaultOutbound,

        [Parameter(ParameterSetName = '/fwmgr/entities/policies/v1:put', Position = 8)]
        [boolean] $MonitorMode
    )
    begin {
        $Fields = @{
            DefaultInbound  = 'default_inbound'
            DefaultOutbound = 'default_outbound'
            MonitorMode     = 'test_mode'
            PlatformId      = 'platform_id'
            PolicyId        = 'policy_id'
            RuleGroupIds    = 'rule_group_ids'
        }
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('platform_id', 'tracking', 'policy_id', 'test_mode', 'enforce', 'default_outbound',
                        'default_inbound', 'rule_group_ids')
                }
            }
        }
        ($Param.Format.Body.root | Where-Object { $_ -ne 'policy_id' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$Param.Inputs.$_) {
                if (!$Existing) {
                    $Existing = Get-FalconFirewallSetting -Ids $Param.Inputs.policy_id -ErrorAction (
                        'SilentlyContinue')
                }
                if ($Existing) {
                    $PSBoundParameters.Add($_,($Existing.$_))
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
Search for Firewall events
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall event identifier(s)
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
.Example
PS>Get-FalconFirewallEvent -Detailed

Return the first set of detailed Firewall event results.
.Example
PS>Get-FalconFirewallEvent -Ids <id>, <id>

Return detailed information about Firewall events <id> and <id>.
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
        [int] $Offset,

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
Search for Firewall fields
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall field identifier(s)
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
.Example
PS>Get-FalconFirewallField -Detailed -All

Retrieve detailed information about all available Firewall fields.
.Example
PS>Get-FalconFirewallField -Ids <id>, <id>

Return detailed information about Firewall fields <id> and <id>.
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
        [int] $Offset,

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
Search for Firewall rule groups
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall rule group identifier(s)
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
.Example
PS>Get-FalconFirewallGroup -Detailed

Retrieve the first set of detailed Firewall group results.
.Example
PS>Get-FalconFirewallGroup -Ids <id>, <id>

Return detailed information about Firewall groups <id> and <id>.
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
        [int] $Offset,

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
Search for Firewall platforms
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall platform identifier(s)
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
.Example
PS>Get-FalconFirewallPlatform -Detailed -All

Retrieve detailed information about all available Firewall platforms.
.Example
PS>Get-FalconFirewallPlatform -Ids <id>, <id>

Return detailed information about Firewall platforms <id> and <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/queries/platforms/v1:get')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/platforms/v1:get', Mandatory = $true, Position = 1)]
        [array] $Ids,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get', Position = 1)]
        [ValidateSet(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/fwmgr/queries/platforms/v1:get', Position = 2)]
        [int] $Offset,

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
Search for Firewall policies
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall policy identifier(s)
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
.Example
PS>Get-FalconFirewallPolicy -Filter "name:!'platform_default'" -Detailed -All

Return detailed information about all Firewall policies not named 'platform_default'.
.Example
PS>Get-FalconFirewallPolicy -Ids <id>, <id>

Return detailed information about Firewall policies <id> and <id>.
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
Search for Firewall policy members
.Description
Requires 'firewall-management:read'.
.Parameter Id
Firewall policy identifier
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
.Example
PS>Get-FalconFirewallPolicyMember -Id <id> -All

Return all identifiers for hosts in the Firewall policy <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/queries/firewall-members/v1:get')]
    param(
        [Parameter(ParameterSetName = '/policy/queries/firewall-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
        [Parameter(ParameterSetName = '/policy/combined/firewall-members/v1:get',
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 1)]
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
Search for Firewall rules
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall rule identifier(s)
.Parameter PolicyId
Return rules in precedence order for a specific Firewall policy
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
.Example
PS>Get-FalconFirewallRule -Detailed

Return the first set of detailed Firewall rule results.
.Example
PS>Get-FalconFirewallRule -Ids <id>, <id>

Return detailed information about Firewall rules <id> and <id>.
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
        [int] $Offset,

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
        Invoke-Falcon @Param | ForEach-Object {
            if ($_.version -and $null -eq $_.version) {
                $_.version = 0
            }
            $_
        }
    }
}
function Get-FalconFirewallSetting {
<#
.Synopsis
List general settings for a Firewall policy
.Description
Requires 'firewall-management:read'.
.Parameter Ids
Firewall policy identifier(s)
.Role
firewall-management:read
.Example
PS>Get-FalconFirewallSetting -Ids <id>, <id>

Retrieve settings for Firewall policies <id> and <id>.
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
Perform actions on Firewall policies
.Description
Requires 'firewall-management:write'.
.Parameter Name
Action to perform
.Parameter Id
Firewall policy identifier
.Parameter GroupId
Host group identifier
.Role
firewall-management:write
.Example
PS>Invoke-FalconFirewallPolicyAction -Name add-host-group -Id <policy_id> -GroupId <group_id>

Add the Host Group <group_id> to Firewall policy <policy_id>.
.Example
PS>Invoke-FalconFirewallPolicyAction -Name enable -Id <policy_id>

Enable Firewall policy <policy_id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall-actions/v1:post')]
    param(
        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('add-host-group', 'disable', 'enable', 'remove-host-group')]
        [string] $Name,

        [Parameter(ParameterSetName = '/policy/entities/firewall-actions/v1:post', Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Position = 2)]
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
            $PSBoundParameters.Add('action_parameters', @(
                @{
                    name  = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            ))
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
Create Firewall rule groups
.Description
Requires 'firewall-management:write'.
.Parameter Name
Firewall rule group name
.Parameter Enabled
Firewall rule group status
.Parameter CloneId
Clone an existing Firewall rule group
.Parameter Library
Clone default Firewall rules
.Parameter Rules
An array of Firewall rule properties
.Parameter Description
Firewall rule group description
.Parameter Comment
Audit log comment
.Role
firewall-management:write
.Example
PS>$Rules = @(@{ name = 'Block Example.com IP'; description = 'Block outbound to example.com IP address';
    platform_ids = @('0'); enabled = $true; action = 'DENY'; direction = 'OUT'; address_family = 'IP4';
    protocol = '*'; fields = @(@{ name = 'network_location'; type = 'set'; values = @( 'ANY' ) });
    local_address = @(@{ address = '*'; netmask = 0 }); remote_address = @(@{ address = '93.184.216.34';
    netmask = 32 })})
PS>New-FalconFirewallGroup -Name Example -Enabled $true -Rules $Rules

Create a Firewall rule group named 'Example' for Windows hosts, with a rule named 'Block example.com' that blocks
outbound IPv4 traffic to the associated IP address (93.184.216.34).
#>
    [CmdletBinding(DefaultParameterSetName = '/fwmgr/entities/rule-groups/v1:post')]
    param(
        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true, Position = 1)]
        [string] $Name,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Mandatory = $true, Position = 2)]
        [boolean] $Enabled,

        [Parameter(ParameterSetName = '/fwmgr/entities/rule-groups/v1:post', Position = 3)]
        [ValidatePattern('^\w{32}$')]
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
Create Firewall policies
.Description
Requires 'firewall-management:write'.
.Parameter Array
An array of Firewall policies to create in a single request
.Parameter PlatformName
Operating System platform
.Parameter Name
Firewall policy name
.Parameter Description
Firewall policy description
.Parameter CloneId
Clone an existing Firewall policy
.Role
firewall-management:write
.Example
PS>New-FalconFirewallPolicy -PlatformName Windows -Name Example

Create Firewall policy 'Example' for Windows hosts.
.Example
PS>New-FalconFirewallPolicy -PlatformName Windows -Name 'Cloned Policy' -CloneId <id>

Create Firewall policy 'Cloned Policy' by cloning the existing Firewall policy <id>.
#>
    [CmdletBinding(DefaultParameterSetName = '/policy/entities/firewall/v1:post')]
    param(
        [Parameter(ParameterSetName = 'array', Mandatory = $true, Position = 1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object   = $Object
                    Command  = 'New-FalconFirewallPolicy'
                    Endpoint = '/policy/entities/firewall/v1:post'
                    Required = @('name', 'platform_name')
                    Content  = @('platform_name')
                    Format   = @{
                        platform_name = 'PlatformName'
                    }
                }
                Confirm-Parameter @Param
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
                Body  = @{
                    resources = @('description', 'platform_name', 'name')
                    root      = @('resources')
                }
                Query = @('clone_id')
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
Remove Firewall rule groups
.Description
Requires 'firewall-management:write'.
.Parameter Ids
Firewall rule group identifier(s)
.Parameter Comment
Audit log comment
.Role
firewall-management:write
.Example
PS>Remove-FalconFirewallGroup -Ids <id>, <id>

Delete Firewall rule groups <id> and <id>.
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
Delete Firewall policies
.Description
Requires 'firewall-management:write'.
.Parameter Ids
Firewall policy identifier(s)
.Role
firewall-management:write
.Example
PS>Remove-FalconFirewallPolicy -Ids <id>, <id>

Delete Firewall policies <id> and <id>.
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
Set Firewall policy precedence
.Description
Requires 'firewall-management:write'.

All Firewall policy identifiers must be supplied in order (with the exception of the 'platform_default' policy)
to define policy precedence.
.Parameter PlatformName
Operating System platform
.Parameter Ids
All Firewall policy identifiers in desired precedence order
.Role
firewall-management:write
.Example
PS>Set-FalconFirewallPrecedence -PlatformName Windows -Ids <id_1>, <id_2>, <id_3>

Set the Firewall policy precedence for 'Windows' policies in order <id_1>, <id_2>, <id_3>. All policy
identifiers must be supplied.
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
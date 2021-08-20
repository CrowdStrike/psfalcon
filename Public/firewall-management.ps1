function Edit-FalconFirewallGroup {
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
function Edit-FalconFirewallGroup {
<#
.SYNOPSIS
Modify Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall Management: Write'.

All fields (plus 'rulegroup_version' and 'tracking') are required when making a rule group change. PSFalcon adds
missing values automatically using data from your existing rule group.

'DiffOperation' array objects must contain 'op', 'path' and 'value' properties. Accepted 'op' values are 'add',
'remove' and 'replace'.

When adding a rule to a rule group,the required rule fields must be included along with a 'temp_id' (in both the
rule properties and in precedence order within 'rule_ids') to establish proper placement of the rule within the
rule group. Simlarly, the value 'null' must be placed within 'rule_versions' in precedence order.
.PARAMETER DiffOperation
An array of hashtables containing rule or rule group changes
.PARAMETER Comment
Audit log comment
.PARAMETER RuleId
Firewall rule 'family' value(s) from the existing rule group [or 'temp_id' for each new rule]
.PARAMETER RuleVersion
Firewall rule version value(s) from the existing rule group [or 'null' for each new rule]
.PARAMETER Id
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Mandatory,Position=1)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'Edit-FalconFirewallGroup'
                    Endpoint = '/fwmgr/entities/rule-groups/v1:patch'
                    Required = @('op','path')
                }
                Confirm-Parameter @Param
                if ($Object.op -notmatch '^(add|remove|replace)$') {
                    $ObjectString = ConvertTo-Json $Object -Compress
                    throw "'$($Object.op)' is not a valid 'op' value. $ObjectString"
                }
            }
        })]
        [Alias('diff_operations','DiffOperations')]
        [object[]]$DiffOperation,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Position=3)]
        [ValidatePattern('^(\d+|[a-fA-F0-9]{32})$')]
        [Alias('rule_ids','RuleIds')]
        [string[]]$RuleId,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Position=4)]
        [ValidatePattern('^(null|\d+)$')]
        [Alias('rule_versions','RuleVersions')]
        [int[]]$RuleVersion,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=6)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('comment')
                Body = @{
                    root = @('rule_ids','tracking','id','diff_type','rule_versions','diff_operations',
                        'rulegroup_version')
                }
            }
        }
    }
    process {
        ($Param.Format.Body.root | Where-Object { $_ -notmatch '^(diff_operations|id)$' }).foreach{
            if (!$PSBoundParameters.$_) {
                # When not provided, add required fields using existing rule group
                if (!$Group) { $Group = try { Get-FalconFirewallGroup -Id $PSBoundParameters.Id -EA 0 } catch {}}
                $PSBoundParameters[$_] = if ($_ -eq 'rulegroup_version') {
                    if ($Group.version) { $Group.version } else { 0 }
                } elseif ($_ -eq 'rule_versions') {
                    if ($PSBoundParameters.RuleId) {
                        (Get-FalconFirewallRule -Id $PSBoundParameters.RuleId).version
                    } else {
                        (Get-FalconFirewallRule -Id $Group.rule_ids).version
                    }
                } else {
                    $Group.$_
                }
            }
        }
        if (!$PSBoundParameters.Tracking) {
            throw "Unable to obtain 'tracking' value from rule group '$($PSBoundParameters.Id)'."
        } else {
            $PSBoundParameters['diff_type'] = 'application/json-patch+json'
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Edit-FalconFirewallPolicy {
<#
.SYNOPSIS
Modify Falcon Firewall Management policies
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Array
An array of policies to modify in a single request
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/firewall/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='array',Mandatory,ValueFromPipeline)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'Edit-FalconFirewallPolicy'
                    Endpoint = '/policy/entities/firewall/v1:patch'
                    Required = @('id')
                    Pattern = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [object[]]$Array,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:patch',Mandatory,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:patch',Position=2)]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:patch',Position=3)]
        [string]$Description
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/firewall/v1:patch'
            Format = @{
                Body = @{
                    resources = @('name','id','description')
                    root = @('resources')
                }
            }
        }
        [System.Collections.Generic.List[object]]$List = @()
    }
    process {
        if ($Array) {
            @($Array).foreach{
                $i = $_
                [string[]]$Select = @('id','name','description').foreach{ if ($i.$_) { $_ }}
                $List.Add(($i | Select-Object $Select))
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            for ($i = 0; $i -lt $List.Count; $i += 100) {
                $PSBoundParameters['Array'] = @($List[$i..($i + 99)])
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Edit-FalconFirewallSetting {
<#
.SYNOPSIS
Modify Falcon Firewall Management policy settings
.DESCRIPTION
Requires 'Firewall Management: Write'.

All fields are required to modify policy settings. PSFalcon adds missing values automatically using data from
your existing policy.

If adding or removing rule groups,all rule groups must be supplied in precedence order.
.PARAMETER PlatformId
Operating System platform identifier
.PARAMETER Enforce
Policy enforcement status
.PARAMETER RuleGroupId
Rule group identifier
.PARAMETER DefaultInbound
Default action for inbound traffic
.PARAMETER DefaultOutbound
Default action for outbound traffic
.PARAMETER MonitorMode
Override all block rules and enable monitoring
.PARAMETER LocalLogging
Enable local logging of firewall events
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/policies/v1:put',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidateSet('0','1')]
        [Alias('platform_id')]
        [string]$PlatformId,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=2)]
        [boolean]$Enforce,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('rule_group_ids','RuleGroupIds')]
        [string[]]$RuleGroupId,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=4)]
        [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
        [Alias('default_inbound')]
        [string]$DefaultInbound,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=5)]
        [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
        [Alias('default_outbound')]
        [string]$DefaultOutbound,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=6)]
        [Alias('test_mode')]
        [boolean]$MonitorMode,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',ValueFromPipelineByPropertyName,
           Position=7)]
        [Alias('local_logging')]
        [boolean]$LocalLogging,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:put',Mandatory,ValueFromPipelineByPropertyName,
            Position=8)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('policy_id','PolicyId')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{
                    root = @('platform_id','tracking','policy_id','test_mode','enforce','default_outbound',
                        'default_inbound','rule_group_ids','local_logging')
                }
            }
        }
    }
    process {
        ($Param.Format.Body.root | Where-Object { $_ -ne 'policy_id' }).foreach{
            # When not provided, add required fields using existing policy settings
            if (!$PSBoundParameters.$_) {
                if (!$Existing) { $Existing = Get-FalconFirewallSetting -Id $Id -EA 0 }
                if ($Existing) { $PSBoundParameters[$_] = $Existing.$_ }
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconFirewallEvent {
<#
.SYNOPSIS
Search for Falcon Firewall Management events
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Event identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/events/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/events/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get')]
        [string]$After,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/events/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','sort','q','offset','after','filter') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconFirewallField {
<#
.SYNOPSIS
Search for Falcon Firewall Management fields
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Field identifier
.PARAMETER PlatformId
Operating System platform
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/firewall-fields/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/firewall-fields/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get',Position=1)]
        [ValidateSet('0','1')]
        [Alias('platform_id')]
        [string]$PlatformId,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get',Position=2)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/firewall-fields/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit','platform_id') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconFirewallGroup {
<#
.SYNOPSIS
Search for Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Rule group identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/rule-groups/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get')]
        [string]$After,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/rule-groups/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','ids','sort','q','offset','after','filter') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconFirewallPlatform {
<#
.SYNOPSIS
Search for Falcon Firewall Management platforms
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Platform identifier
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/platforms/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/platforms/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateSet('0','1')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/platforms/v1:get',Position=1)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/platforms/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/platforms/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/platforms/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/platforms/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','offset','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconFirewallPolicy {
<#
.SYNOPSIS
Search for Falcon Firewall Management policies
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Policy identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Include
Include additional properties
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/firewall/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get',Position=1)]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get',Position=2)]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get',Position=2)]
        [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc',
            'enabled.asc','enabled.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc',
            'modified_timestamp.desc','name.asc','name.desc','platform_name.asc','platform_name.desc',
            'precedence.asc','precedence.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get',Position=3)]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get',Position=3)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:get',Position=2)]
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get',Position=4)]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get',Position=4)]
        [ValidateSet('members','settings',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get')]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/policy/combined/firewall/v1:get')]
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/queries/firewall/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
        if ($Request -and $Include) {
            $Request = Add-Include $Request $PSBoundParameters @{
                members = 'Get-FalconFirewallPolicyMember'
                settings = 'Get-FalconFirewallSetting'
            }
        }
        $Request
    }
}
function Get-FalconFirewallPolicyMember {
<#
.SYNOPSIS
Search for Falcon Firewall Management policy members
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Policy identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/firewall-members/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get',Position=2)]
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get',Position=2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get',Position=3)]
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get',Position=4)]
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get')]
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get',Mandatory)]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/policy/combined/firewall-members/v1:get')]
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/queries/firewall-members/v1:get')]
        [switch]$Total

    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','id','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconFirewallRule {
<#
.SYNOPSIS
Search for Falcon Firewall Management rules
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Rule identifier
.PARAMETER PolicyId
Return rules in precedence order for a specific policy
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/rules/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rules/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [Alias('Ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get',Mandatory,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$PolicyId,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get',Position=2)]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get',Position=3)]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get',Position=4)]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get',Position=5)]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get')]
        [string]$After,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/policy-rules/v1:get')]
        [Parameter(ParameterSetName='/fwmgr/queries/rules/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('limit','sort','q','offset','after','filter','id') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            @(Invoke-Falcon @Param -Inputs $PSBoundParameters).foreach{
                if ($_.version -and $null -eq $_.version) { $_.version = 0 }
                $_
            }
        }
    }
    end {
        if ($List) {
            $Param['Format'] = @{ Query = @('ids') }
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            [object[]]$Request = @(Invoke-Falcon @Param -Inputs $PSBoundParameters).foreach{
                if ($_.version -and $null -eq $_.version) { $_.version = 0 }
                $_
            }
            foreach ($i in $List) {
                # Return rules in order of provided 'Id' value(s)
                [string]$IdField = if ($i -match '^\d+$') { 'id' } else { 'family' }
                $Request | Where-Object { $_.$IdField -eq $i }
            }
        }
    }
}
function Get-FalconFirewallSetting {
<#
.SYNOPSIS
Retrieve general settings for a Falcon Firewall Management policy
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/policies/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Invoke-FalconFirewallPolicyAction {
<#
.SYNOPSIS
Perform actions on Falcon Firewall Management policies
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/firewall-actions/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/firewall-actions/v1:post',Mandatory,Position=1)]
        [ValidateSet('add-host-group','disable','enable','remove-host-group',IgnoreCase=$false)]
        [Alias('action_name')]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/firewall-actions/v1:post',Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/firewall-actions/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('action_name')
                Body = @{ root = @('ids','action_parameters') }
            }
        }
    }
    process {
        $PSBoundParameters['Ids'] = @($PSBoundParameters.Id)
        [void]$PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $PSBoundParameters['action_parameters'] = @(
                @{
                    name = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            )
            [void]$PSBoundParameters.Remove('GroupId')
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function New-FalconFirewallGroup {
<#
.SYNOPSIS
Create Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Name
Rule group name
.PARAMETER Enabled
Rule group status
.PARAMETER Description
Rule group description
.PARAMETER Rule
Firewall rules
.PARAMETER Comment
Audit log comment
.PARAMETER Library
Clone default Firewall rules
.PARAMETER CloneId
Clone an existing rule group
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [boolean]$Enabled,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [string]$Description,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [Alias('rules')]
        [object[]]$Rule,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=5)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=6)]
        [string]$Library,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=7)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('clone_id','id')]
        [string]$CloneId
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('library','comment','clone_id')
                Body = @{ root = @('enabled','name','rules','description') }
            }
        }
    }
    process {
        if ($PSBoundParameters.Rule) {
            $Fields = @('name','description','enabled','platform_ids','direction','action','address_family',
                'local_address','remote_address','protocol','local_port','remote_port','icmp','monitor','fields')
            [object[]] $PSBoundParameters.Rule = foreach ($i in $PSBoundParameters.Rule) {
                # Filter 'rule' to required properties that contain a value
                $Select = @($Fields).foreach{ if ($i.$_) { $_ } }
                $i | Select-Object $Select
            }
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function New-FalconFirewallPolicy {
<#
.SYNOPSIS
Create Falcon Firewall Management policies
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Array
An array of policies to create in a single request
.PARAMETER Name
Policy name
.PARAMETER PlatformName
Operating system platform
.PARAMETER Description
Policy description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/firewall/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='array',Mandatory,ValueFromPipeline)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'New-FalconFirewallPolicy'
                    Endpoint = '/policy/entities/firewall/v1:post'
                    Required = @('name','platform_name')
                    Content = @('platform_name')
                    Format = @{ platform_name = 'PlatformName' }
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [object[]]$Array,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:post',Mandatory,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:post',Mandatory,Position=2)]
        [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
        [Alias('platform_name')]
        [string]$PlatformName,
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:post',Position=3)]
        [string]$Description
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/firewall/v1:post'
            Format = @{
                Body = @{
                    resources = @('description','platform_name','name')
                    root = @('resources')
                }
            }
        }
        [System.Collections.Generic.List[object]]$List = @()
    }
    process {
        if ($Array) {
            foreach ($i in $Array) {
                # Select allowed fields, when populated
                [string[]]$Select = @('name','description','platform_name').foreach{ if ($i.$_) { $_ }}
                $List.Add(($i | Select-Object $Select))
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            for ($i = 0; $i -lt $List.Count; $i += 100) {
                $PSBoundParameters['Array'] = @($List[$i..($i + 99)])
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Remove-FalconFirewallGroup {
<#
.SYNOPSIS
Remove Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Rule group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids','comment') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Remove-FalconFirewallPolicy {
<#
.SYNOPSIS
Remove Falcon Firewall Management policies
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/firewall/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/firewall/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Set-FalconFirewallPrecedence {
<#
.SYNOPSIS
Set Falcon Firewall Management policy precedence
.DESCRIPTION
Requires 'Firewall Management: Write'.

All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to define
policy precedence.
.PARAMETER PlatformName
Operating system platform
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/firewall-precedence/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/policy/entities/firewall-precedence/v1:post',Mandatory,Position=1)]
        [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
        [Alias('platform_name')]
        [string]$PlatformName,
        [Parameter(ParameterSetName='/policy/entities/firewall-precedence/v1:post',Mandatory,Position=2)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('platform_name','ids') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
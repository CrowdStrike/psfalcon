function Edit-FalconFirewallGroup {
<#
.SYNOPSIS
Modify Falcon Firewall Management rule groups
.DESCRIPTION
All fields (plus 'rulegroup_version' and 'tracking') are required when making a rule group change. PSFalcon adds
missing values automatically using data from your existing rule group.

'DiffOperation' array objects must contain 'op', 'path' and 'value' properties. Accepted 'op' values are 'add',
'remove' and 'replace'.

When adding a rule to a rule group,the required rule fields must be included along with a 'temp_id' (in both the
rule properties and in precedence order within 'rule_ids') to establish proper placement of the rule within the
rule group. Simlarly, the value 'null' must be placed within 'rule_versions' in precedence order.

Requires 'Firewall Management: Write'.
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
.PARAMETER Validate
Toggle to perform validation, instead of modifying rule group
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFirewallGroup
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:patch',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Mandatory,Position=1)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Mandatory,Position=1)]
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
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Position=3)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Position=3)]
        [ValidatePattern('^(\d+|[a-fA-F0-9]{32})$')]
        [Alias('rule_ids','RuleIds')]
        [string[]]$RuleId,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Position=4)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Position=4)]
        [ValidatePattern('^(null|\d+)$')]
        [Alias('rule_versions','RuleVersions')]
        [int[]]$RuleVersion,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Mandatory)]
        [switch]$Validate
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
function Edit-FalconFirewallSetting {
<#
.SYNOPSIS
Modify Falcon Firewall Management policy settings
.DESCRIPTION
All fields are required to modify policy settings. PSFalcon adds missing values automatically using data from
your existing policy.

If adding or removing rule groups, all rule groups must be supplied in precedence order.

Requires 'Firewall Management: Write'.
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
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFirewallSetting
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/policies/v2:put',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=1)]
        [ValidateSet('0','1')]
        [Alias('platform_id')]
        [string]$PlatformId,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=2)]
        [boolean]$Enforce,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=3)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('rule_group_ids','RuleGroupIds')]
        [string[]]$RuleGroupId,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=4)]
        [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
        [Alias('default_inbound')]
        [string]$DefaultInbound,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=5)]
        [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
        [Alias('default_outbound')]
        [string]$DefaultOutbound,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=6)]
        [Alias('test_mode')]
        [boolean]$MonitorMode,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,
           Position=7)]
        [Alias('local_logging')]
        [boolean]$LocalLogging,
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',Mandatory,ValueFromPipelineByPropertyName,
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallEvent
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/events/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/events/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallField
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/firewall-fields/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/firewall-fields/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallGroup
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/rule-groups/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconFirewallLocation {
<#
.SYNOPSIS
Search for Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall Management: Read'.
.PARAMETER Id
Location identifier
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
https://github.com/crowdstrike/psfalcon/wiki/
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/network-locations/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/network-locations-details/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get',Position=1)]
        [string]$Filter,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get',Position=2)]
        [Alias('q')]
        [string]$Query,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get',Position=3)]
        [string]$Sort,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get',Position=4)]
        [int]$Limit,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get')]
        [string]$Offset,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get')]
        [string]$After,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('filter','q','after','limit','sort','offset','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallPlatform
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/platforms/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/platforms/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallRule
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/rules/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rules/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
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
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $Param['Format'] = @{ Query = @('ids') }
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
        }
        $Request = @(Invoke-Falcon @Param -Inputs $PSBoundParameters).foreach{
            if ($_.version -and $null -eq $_.version) { $_.version = 0 }
            $_
        }
        if ($List) {
            foreach ($i in $List) {
                # Return rules in order of provided 'Id' value(s)
                [string]$IdField = if ($i -match '^\d+$') { 'id' } else { 'family' }
                $Request | Where-Object { $_.$IdField -eq $i }
            }
        } else {
            $Request
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallSetting
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/policies/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/policies/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline,Position=1)]
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
.PARAMETER Platform
Operating system platform [default: 0 (Windows)]
.PARAMETER Validate
Toggle to perform validation, instead of creating rule group
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFirewallGroup
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory,
            ValueFromPipelineByPropertyName,Position=2)]
        [boolean]$Enabled,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=3)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',
            ValueFromPipelineByPropertyName,Position=3)]
        [string]$Description,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=4)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',
            ValueFromPipelineByPropertyName,Position=4)]
        [Alias('rules')]
        [object[]]$Rule,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=5)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',
            ValueFromPipelineByPropertyName,Position=5)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=6)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Position=6)]
        [string]$Library,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=7)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Position=7)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('clone_id','id')]
        [string]$CloneId,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,
            Position=8)]
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',
            ValueFromPipelineByPropertyName,Position=8)]
        [string]$Platform,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory)]
        [switch]$Validate
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('library','comment','clone_id')
                Body = @{ root = @('enabled','name','rules','description','platform') }
            }
        }
    }
    process {
        if ($PSBoundParameters.Rule) {
            [object[]]$PSBoundParameters.Rule = Confirm-Property 'name','description','enabled','platform_ids',
                'direction','action','address_family','local_address','remote_address','protocol','local_port',
                'remote_port','icmp','monitor','fields' $PSBoundParameters.Rule
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
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
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFirewallGroup
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rule-groups/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:delete',Position=1)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
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
function Remove-FalconFirewallLocation {
<#
.SYNOPSIS
Remove Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Id
Location identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconFirewallLocation
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/network-locations/v1:delete',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:delete',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [Alias('ids')]
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
function Set-FalconFirewallLocationPrecedence {
<#
.SYNOPSIS
Set Falcon Firewall Management location precedence
.DESCRIPTION
Requires 'Firewall Management: Write'.
.PARAMETER Cid
Customer identifier
.PARAMETER Comment
Audit log comment
.PARAMETER Id
Location identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconFirewallLocationPrecedence
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',Position=1)]
        [string]$Cid,
        [Parameter(ParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',Position=2)]
        [string]$Comment,
        [Parameter(ParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',Mandatory,Position=3)]
        [Alias('location_precedence')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Body = @{ root = @('cid','location_precedence') }
                Query = @('comment')
            }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Test-FalconFirewallPath {
<#
.SYNOPSIS
Validate that a string matches a Firewall Management executable filepath glob pattern
.DESCRIPTION
Requires 'Firewall management: Write'.
.PARAMETER Pattern
Glob pattern
.PARAMETER String
Filepath string
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconFirewallRulePath
#>
    [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/rules/validate-filepath/v1:post',
        SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/fwmgr/entities/rules/validate-filepath/v1:post',Mandatory,Position=1)]
        [Alias('filepath_pattern')]
        [string]$Pattern,
        [Parameter(ParameterSetName='/fwmgr/entities/rules/validate-filepath/v1:post',Mandatory,Position=2)]
        [Alias('filepath_test_string')]
        [string]$String
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('filepath_test_string','filepath_pattern') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
Register-ArgumentCompleter -CommandName New-FalconFirewallGroup -ParameterName Platform -ScriptBlock {
    (Get-FalconFirewallPlatform -Detailed -EA 0).label }
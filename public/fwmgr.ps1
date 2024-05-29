function Edit-FalconFirewallGroup {
<#
.SYNOPSIS
Modify Falcon Firewall Management rule groups
.DESCRIPTION
All fields (plus 'rulegroup_version' and 'tracking') are required when making a rule group change. PSFalcon adds
missing values automatically using data from your existing rule group.

'DiffOperation' array objects must contain 'from', 'op', 'path' and 'value' properties. Accepted 'op' values are
'add', 'remove' and 'replace'.

When adding a rule to a rule group,the required rule fields must be included along with a 'temp_id' (in both the
rule properties and in precedence order within 'rule_ids') to establish proper placement of the rule within the
rule group. Simlarly, the value 'null' must be placed within 'rule_versions' in precedence order.

Requires 'Firewall management: Write'.
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
    [string[]]$RuleVersion,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=5)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:patch',Mandatory)]
    [switch]$Validate
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($DiffOperation) {
      @($DiffOperation).foreach{
        # Filter to defined 'diff_operations' properties
        [PSCustomObject]$i = $_ | Select-Object $Param.Format.Body.diff_operations
        if ($i.op -and $i.op -notmatch '^(add|remove|replace)$') {
          # Ignore if 'op' is an unexpected value
          $ObjectString = ConvertTo-Json $i -Compress
          Write-Error "'$($i.op)' is not a valid 'op' value. $ObjectString"
        } else {
          $List.Add($i)
        }
      }
    }
  }
  end {
    if ($PSCmdlet.ShouldProcess('Edit-FalconFirewallGroup','Get-FalconFirewallGroup')) {
      # Remove remaining 'DiffOperation' value
      [void]$PSBoundParameters.Remove('DiffOperation')
      @($Param.Format.Body.root).Where({$_ -ne 'id'}).foreach{
        if (!$PSBoundParameters.$_) {
          # When not provided, add required fields using existing rule group
          if (!$Group) { $Group = try { Get-FalconFirewallGroup -Id $PSBoundParameters.Id -EA 0 } catch {} }
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
      if (!$PSBoundParameters.Tracking) { throw "Unable to obtain 'tracking' value from rule group '$($Id)'." }
    }
    # Add 'diff_type', add 'diff_operations' as an array and modify 'Format'
    $PSBoundParameters['diff_type'] = 'application/json-patch+json'
    $PSBoundParameters['diff_operations'] = @($List)
    [void]$Param.Format.Body.Remove('diff_operations')
    $Param.Format.Body.root += 'diff_operations'
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconFirewallLocation {
<#
.SYNOPSIS
Modify Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall management: Write'.
.PARAMETER Id
Location identifier
.PARAMETER Name
Location name
.PARAMETER Description
Location description
.PARAMETER Enabled
Location status
.PARAMETER ConnectionType
Wired or wireless connection types with associated properties
.PARAMETER DefaultGateway
Default gateway IP address or CIDR block
.PARAMETER DhcpServer
DHCP server IP address or CIDR block
.PARAMETER DnsServer
DNS server IP address or CIDR block
.PARAMETER HostAddress
Host IP address or CIDR block
.PARAMETER DnsResolutionTarget
Target IP address or CIDR block, with optional domain name
.PARAMETER HttpsReachableHost
Target domain name using a trusted certificate
.PARAMETER IcmpRequestTarget
Pingable IP address or CIDR block
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFirewallLocation
#>
  [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/network-locations/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=4)]
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=5)]
    [Alias('connection_types')]
    [object]$ConnectionType,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=6)]
    [Alias('default_gateways')]
    [string[]]$DefaultGateway,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=7)]
    [Alias('dhcp_servers')]
    [string[]]$DhcpServer,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=8)]
    [Alias('dns_servers')]
    [string[]]$DnsServer,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=9)]
    [Alias('host_addresses')]
    [string[]]$HostAddress,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=10)]
    [Alias('dns_resolution_targets')]
    [object[]]$DnsResolutionTarget,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=11)]
    [Alias('https_reachable_hosts')]
    [string[]]$HttpsReachableHost,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=12)]
    [Alias('icmp_request_targets')]
    [string[]]$IcmpRequestTarget,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:patch',Position=13)]
    [string]$Comment
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('https_reachable_hosts','dhcp_servers','name','icmp_request_targets',
            'default_gateways','host_addresses','dns_resolution_targets','description','id',
            'connection_types','enabled','dns_servers')
        }
        Query = @('comment')
      }
    }
  }
  process {
    if ($PSBoundParameters.DnsResolutionTarget) {
      $PSBoundParameters.DnsResolutionTarget = @{ targets = [object[]]$PSBoundParameters.DnsResolutionTarget }
    }
    if ($PSBoundParameters.HttpsReachableHost) {
      $PSBoundParameters.HttpsReachableHost = @{ hostnames = [string[]]$PSBoundParameters.HttpsReachableHost }
    }
    if ($PSBoundParameters.IcmpRequestTarget) {
      $PSBoundParameters.IcmpRequestTarget = @{ targets = [string[]]$PSBoundParameters.IcmpRequestTarget }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconFirewallLocationSetting {
<#
.SYNOPSIS
Modify Falcon Firewall Management settings for all locations
.DESCRIPTION
Requires 'Firewall management: Write'.
.PARAMETER Cid
Customer identifier
.PARAMETER IcmpInterval
Number of seconds between each ICMP request attempt
.PARAMETER DnsInterval
Number of seconds between each DNS request attempt
.PARAMETER HttpsInterval
Number of seconds between each HTTPS request attempt
.PARAMETER LocationPrecedence
Location identifiers in desired precedence order
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconFirewallLocationSetting
#>
  [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=2)]
    [Alias('icmp_request_targets_polling_interval')]
    [int32]$IcmpInterval,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=3)]
    [Alias('dns_resolution_targets_polling_interval')]
    [int32]$DnsInterval,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=4)]
    [Alias('https_reachable_hosts_polling_interval')]
    [int32]$HttpsInterval,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('location_precedence')]
    [string[]]$LocationPrecedence,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-metadata/v1:post',Position=6)]
    [string]$Comment
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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

Requires 'Firewall management: Write'.
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
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=1)]
    [ValidateSet('0','1')]
    [Alias('platform_id')]
    [string]$PlatformId,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=2)]
    [boolean]$Enforce,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_group_ids','RuleGroupIds')]
    [string[]]$RuleGroupId,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=4)]
    [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
    [Alias('default_inbound')]
    [string]$DefaultInbound,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=5)]
    [ValidateSet('ALLOW','DENY',IgnoreCase=$false)]
    [Alias('default_outbound')]
    [string]$DefaultOutbound,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=6)]
    [Alias('test_mode')]
    [boolean]$MonitorMode,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',ValueFromPipelineByPropertyName,Position=7)]
    [Alias('local_logging')]
    [boolean]$LocalLogging,
    [Parameter(ParameterSetName='/fwmgr/entities/policies/v2:put',Mandatory,ValueFromPipelineByPropertyName,
      Position=8)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('policy_id','PolicyId')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSCmdlet.ShouldProcess('Edit-FalconFirewallSetting','Get-FalconFirewallPolicy')) {
      $Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
      if ($Format) {
        ($Format.Body.root | Where-Object { $_ -ne 'policy_id' }).foreach{
          # When not provided, add required fields using existing policy settings
          if (!$PSBoundParameters.$_) {
            if (!$Existing) { $Existing = Get-FalconFirewallSetting -Id $Id -EA 0 }
            if ($Existing) { $PSBoundParameters[$_] = $Existing.$_ }
          }
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconFirewallEvent {
<#
.SYNOPSIS
Search for Falcon Firewall Management events
.DESCRIPTION
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFirewallField {
<#
.SYNOPSIS
Search for Falcon Firewall Management fields
.DESCRIPTION
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFirewallGroup {
<#
.SYNOPSIS
Search for Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFirewallLocation {
<#
.SYNOPSIS
Search for Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall management: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconFirewallLocation
#>
  [CmdletBinding(DefaultParameterSetName='/fwmgr/queries/network-locations/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-details/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/fwmgr/queries/network-locations/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFirewallPlatform {
<#
.SYNOPSIS
Search for Falcon Firewall Management platforms
.DESCRIPTION
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconFirewallRule {
<#
.SYNOPSIS
Search for Falcon Firewall Management rules
.DESCRIPTION
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
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
      $PSBoundParameters['Id'] = $List
    }
    $Request = @(Invoke-Falcon @Param -UserInput $PSBoundParameters).foreach{
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
Requires 'Firewall management: Read'.
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
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconFirewallGroup {
<#
.SYNOPSIS
Create Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall management: Write'.
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
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,Position=3)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,Position=4)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('rules')]
    [object[]]$Rule,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,Position=5)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [string]$Comment,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=6)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Position=6)]
    [string]$Library,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',Position=7)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('clone_id','id')]
    [string]$CloneId,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/v1:post',ValueFromPipelineByPropertyName,Position=8)]
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',ValueFromPipelineByPropertyName,
      Position=8)]
    [string]$Platform,
    [Parameter(ParameterSetName='/fwmgr/entities/rule-groups/validation/v1:post',Mandatory)]
    [switch]$Validate
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($Rule) {
      @($Rule).foreach{
        # Filter to defined 'rules' properties and remove empty values
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.rules
        Remove-EmptyValue $i name,description,comment
        $List.Add($i)
      }
    }
  }
  end {
    if ($List) {
      # Add 'rules' as an array and remove remaining value
      $PSBoundParameters['rules'] = @($List)
      [void]$PSBoundParameters.Remove('Rule')
    }
    # Modify 'Format' to ensure 'rules' is properly appended and make request
    [void]$Param.Format.Body.Remove('rules')
    $Param.Format.Body.root += 'rules'
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function New-FalconFirewallLocation {
<#
.SYNOPSIS
Create Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall management: Write'.
.PARAMETER CloneId
Clone an existing location
.PARAMETER AddFwRule
Include firewall rules from existing location
.PARAMETER Name
Location name
.PARAMETER Description
Location description
.PARAMETER Enabled
Location status
.PARAMETER ConnectionType
Wired or wireless connection types with associated properties
.PARAMETER DefaultGateway
Default gateway IP address or CIDR block
.PARAMETER DhcpServer
DHCP server IP address or CIDR block
.PARAMETER DnsServer
DNS server IP address or CIDR block
.PARAMETER HostAddress
Host IP address or CIDR block
.PARAMETER DnsResolutionTarget
Target IP address or CIDR block, with optional domain name
.PARAMETER HttpsReachableHost
Target domain name using a trusted certificate
.PARAMETER IcmpRequestTarget
Pingable IP address or CIDR block
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconFirewallLocation
#>
  [CmdletBinding(DefaultParameterSetName='/fwmgr/entities/network-locations/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='CloneId',Mandatory,ValueFromPipelineByPropertyName,Position=1)]
    [Alias('clone_id','id')]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$CloneId,
    [Parameter(ParameterSetName='CloneId',Position=2)]
    [Alias('add_fw_rules')]
    [boolean]$AddFwRule,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=3)]
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=4)]
    [Alias('connection_types')]
    [object]$ConnectionType,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=5)]
    [Alias('default_gateways')]
    [string[]]$DefaultGateway,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=6)]
    [Alias('dhcp_servers')]
    [string[]]$DhcpServer,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=7)]
    [Alias('dns_servers')]
    [string[]]$DnsServer,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=8)]
    [Alias('host_addresses')]
    [string[]]$HostAddress,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=9)]
    [Alias('dns_resolution_targets')]
    [object[]]$DnsResolutionTarget,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=10)]
    [Alias('https_reachable_hosts')]
    [string[]]$HttpsReachableHost,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=11)]
    [Alias('icmp_request_targets')]
    [string[]]$IcmpRequestTarget,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations/v1:post',Position=12)]
    [string]$Comment
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/fwmgr/entities/network-locations/v1:post'
      Format = @{
        Body = @{
          root = @('description','dhcp_servers','name','https_reachable_hosts','icmp_request_targets',
            'default_gateways','host_addresses','dns_resolution_targets','connection_types',
            'dns_servers','enabled')
        }
        Query = @('clone_id','comment','add_fw_rules')
      }
    }
  }
  process {
    if ($PSBoundParameters.DnsResolutionTarget) {
      $PSBoundParameters.DnsResolutionTarget = @{ targets = [object[]]$PSBoundParameters.DnsResolutionTarget }
    }
    if ($PSBoundParameters.HttpsReachableHost) {
      $PSBoundParameters.HttpsReachableHost = @{ hostnames = [string[]]$PSBoundParameters.HttpsReachableHost }
    }
    if ($PSBoundParameters.IcmpRequestTarget) {
      $PSBoundParameters.IcmpRequestTarget = @{ targets = [string[]]$PSBoundParameters.IcmpRequestTarget }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconFirewallGroup {
<#
.SYNOPSIS
Remove Falcon Firewall Management rule groups
.DESCRIPTION
Requires 'Firewall management: Write'.
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
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconFirewallLocation {
<#
.SYNOPSIS
Remove Falcon Firewall Management locations
.DESCRIPTION
Requires 'Firewall management: Write'.
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
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconFirewallLocationPrecedence {
<#
.SYNOPSIS
Set Falcon Firewall Management location precedence
.DESCRIPTION
Requires 'Firewall management: Write'.
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
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',Position=2)]
    [string]$Comment,
    [Parameter(ParameterSetName='/fwmgr/entities/network-locations-precedence/v1:post',Mandatory,Position=3)]
    [Alias('location_precedence')]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
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
https://github.com/crowdstrike/psfalcon/wiki/Test-FalconFirewallPath
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
Register-ArgumentCompleter -CommandName New-FalconFirewallGroup -ParameterName Platform -ScriptBlock {
  (Get-FalconFirewallPlatform -Detailed -EA 0).label }
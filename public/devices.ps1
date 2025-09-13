function Add-FalconGroupingTag {
<#
.SYNOPSIS
Add FalconGroupingTags to Hosts
.DESCRIPTION
Requires 'Hosts: Write'.
.PARAMETER Tag
FalconGroupingTag value ['FalconGroupingTags/<string>']
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconGroupingTag
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/devices/tags/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/devices/tags/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^FalconGroupingTags/.+$')]
    [ValidateScript({
      @($_).foreach{
        if ((Test-RegexValue $_) -eq 'tag') { $true } else {
          throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
        }
      }
    })]
    [Alias('Tags')]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/devices/entities/devices/tags/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('device_ids','device_id','ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $PSBoundParameters['action'] = 'add'
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Edit-FalconHostGroup {
<#
.SYNOPSIS
Modify a host group
.DESCRIPTION
Requires 'Host groups: Write'.
.PARAMETER Name
Host group name
.PARAMETER Description
Host group description
.PARAMETER AssignmentRule
FQL-based assignment rule, used with dynamic host groups
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/host-groups/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('assignment_rule')]
    [string]$AssignmentRule,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconHost {
<#
.SYNOPSIS
Search for hosts
.DESCRIPTION
Requires 'Hosts: Read' plus related permission(s) for 'Include' selection(s).
.PARAMETER Id
Host identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Include
Include additional properties
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Field
Host properties to include in response
.PARAMETER Hidden
Restrict search to 'hidden' hosts
.PARAMETER Login
Retrieve user login history
.PARAMETER Network
Retrieve network address history
.PARAMETER State
Retrieve online status
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHost
#>
  [CmdletBinding(DefaultParameterSetName='/devices/queries/devices-scroll/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/devices/v2:post',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/devices/combined/devices/login-history/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/devices/combined/devices/network-address-history/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/devices/entities/online-state/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get',Position=1)]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get',Position=1)]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Position=1)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Position=2)]
    [ValidateSet('device_id.asc','device_id.desc','agent_load_flags.asc','agent_load_flags.desc',
      'agent_version.asc','agent_version.desc','bios_manufacturer.asc','bios_manufacturer.desc',
      'bios_version.asc','bios_version.desc','config_id_base.asc','config_id_base.desc',
      'config_id_build.asc','config_id_build.desc','config_id_platform.asc','config_id_platform.desc',
      'cpu_signature.asc','cpu_signature.desc','external_ip.asc','external_ip.desc',
      'filesystem_containment_status.asc','filesystem_containment_status.desc','first_seen.asc',
      'first_seen.desc','hostname.asc','hostname.desc','instance_id.asc','instance_id.desc',
      'last_login_timestamp.asc','last_login_timestamp.desc','last_seen.asc','last_seen.desc',
      'local_ip.asc','local_ip.desc','local_ip.raw.asc','local_ip.raw.desc','mac_address.asc',
      'mac_address.desc','machine_domain.asc','machine_domain.desc','major_version.asc',
      'major_version.desc','minor_version.asc','minor_version.desc','modified_timestamp.asc',
      'modified_timestamp.desc','os_version.asc','os_version.desc','ou.asc','ou.desc','platform_id.asc',
      'platform_id.desc','platform_name.asc','platform_name.desc','product_type_desc.asc',
      'product_type_desc.desc','reduced_functionality_mode.asc','reduced_functionality_mode.desc',
      'release_group.asc','release_group.desc','serial_number.asc','serial_number.desc','site_name.asc',
      'site_name.desc','status.asc','status.desc','system_manufacturer.asc','system_manufacturer.desc',
      'system_product_name.asc','system_product_name.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get',Position=3)]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get',Position=3)]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Position=3)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Position=3)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get',Position=4)]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get',Position=4)]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Position=4)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Position=4)]
    [ValidateSet('content_state','group_names','login_history','network_history','online_state','policy_names',
      'zero_trust_assessment',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Position=5)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Position=5)]
    [Alias('fields')]
    [string[]]$Field,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get')]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Mandatory)]
    [switch]$Hidden,
    [Parameter(ParameterSetName='/devices/combined/devices/login-history/v2:post',Mandatory)]
    [switch]$Login,
    [Parameter(ParameterSetName='/devices/combined/devices/network-address-history/v1:post',Mandatory)]
    [switch]$Network,
    [Parameter(ParameterSetName='/devices/entities/online-state/v1:get',Mandatory)]
    [switch]$State,
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get')]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/devices/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/devices-hidden/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/devices/queries/devices-scroll/v1:get')]
    [Parameter(ParameterSetName='/devices/queries/devices-hidden/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Max = if ($PSCmdlet.ParameterSetName -eq '/devices/entities/devices/v2:post') {
        5000
      } elseif ($PSCmdlet.ParameterSetName -eq '/devices/entities/online-state/v1:get') {
        100
      } elseif ($PSCmdlet.ParameterSetName -eq '/devices/combined/devices/login-history/v2:post') {
        10
      } else {
        500
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    if ($Include -and $PSCmdlet.ParameterSetName -match '/devices/combined/devices(-hidden)?/v1:get' -and
    $PSBoundParameters.Field) {
      @(@('group_names','groups'),@('policy_names','device_policies')).foreach{
        # Error if 'fields' does not contain required property for relevant 'Include' value
        if ($Include -contains $_[0] -and $PSBoundParameters.Field -notcontains $_[1]) {
          throw ('"Field" must contain "{1}" when "{0}" is provided with "Include"!' -f $_[0],$_[1])
        }
      }
      @(@($Include).Where({$_ -notmatch '^(group|policy)_names$'}) | Select-Object -First 1).foreach{
        if ($PSBoundParameters.Field -notcontains 'device_id') {
          # Error if 'fields' does not contain 'device_id' for other 'Include' values
          throw ('"Field" must contain "device_id" when "{0}" is provided with "Include"!' -f $_)
        }
      }
    }
    if ($PSBoundParameters.Limit -and $PSBoundParameters.Limit -gt 5000) {
      if ($PSCmdlet.ParameterSetName -notmatch '/devices/combined/devices(-hidden)?/v1:get') {
        # Set 'limit' to max of 5,000 if not using /devices/combined/ endpoint
        $PSBoundParameters.Limit = 5000
      }
    }
    # Convert 'fields' into single, comma delimited string
    if ($PSBoundParameters.Field) { $PSBoundParameters.Field = $PSBoundParameters.Field -join ',' }
    $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
    if ($Request -and $Include) {
      if (!$Request.device_id) {
        # Convert list of 'device_id' values into objects with 'device_id' and other required properties
        $Request = if ($Include) {
          [string[]]$Select = 'device_id'
          $Select += switch ($Include) {
            { $_ -contains 'group_names' } { 'groups' }
            { $_ -contains 'policy_names' } { 'device_policies' }
          }
          & $MyInvocation.MyCommand.Name -Id $Request | Select-Object $Select
        } else {
          @($Request).foreach{ ,[PSCustomObject]@{ device_id = $_ }}
        }
      }
      if ($Include -contains 'content_state') {
        foreach ($i in (Get-FalconContentState -Id $Request.device_id -EA 0)) {
          $SetParam = @{
            Object = $Request | Where-Object { $_.device_id -eq $i.device_id }
            Name = 'content_state'
            Value = $i | Select-Object system_critical,rapid_response_content,vulnerability_management,
              sensor_operations
          }
          Set-Property @SetParam
        }
      }
      if ($Include -contains 'group_names') {
        $Groups = try { $Request.groups | Get-FalconHostGroup -EA 0 | Select-Object id,name } catch {}
        if ($Groups) {
          foreach ($i in $Request) {
            if ($i.groups) { $i.groups = $Groups | Where-Object { $i.groups -contains $_.id }}
          }
        }
      }
      if ($Include -contains 'login_history') {
        foreach ($i in (& $MyInvocation.MyCommand.Name -Id $Request.device_id -Login -EA 0)) {
          $SetParam = @{
            Object = $Request | Where-Object { $_.device_id -eq $i.device_id }
            Name = 'login_history'
            Value = $i.recent_logins
          }
          Set-Property @SetParam
        }
      }
      if ($Include -contains 'network_history') {
        foreach ($i in (& $MyInvocation.MyCommand.Name -Id $Request.device_id -Network -EA 0)) {
          $SetParam = @{
            Object = $Request | Where-Object { $_.device_id -eq $i.device_id }
            Name = 'network_history'
            Value = $i.history
          }
          Set-Property @SetParam
        }
      }
      if ($Include -contains 'online_state') {
        foreach ($i in (& $MyInvocation.MyCommand.Name -Id $Request.device_id -State -EA 0)) {
          $SetParam = @{
            Object = $Request | Where-Object { $_.device_id -eq $i.id }
            Name = 'online_state'
            Value = $i
          }
          Set-Property @SetParam
        }
      }
      if ($Include -contains 'policy_names') {
        @('device_control','firewall','prevention','remote_response','sensor_update').foreach{
          foreach ($i in (& "Get-Falcon$($_ -replace '(remote)?_',$null)Policy" -Id (
          $Request.device_policies.$_.policy_id | Select-Object -Unique) -EA 0)) {
            @($Request.device_policies.$_).Where({$_.policy_id -eq $i.id}).foreach{
              Set-Property $_ 'policy_name' $i.name
            }
          }
        }
      }
      if ($Include -contains 'zero_trust_assessment') {
        foreach ($i in (Get-FalconZta -Id $Request.device_id -EA 0)) {
          $SetParam = @{
            Object = $Request | Where-Object { $_.device_id -eq $i.aid }
            Name = 'zero_trust_assessment'
            Value = $i | Select-Object modified_time,sensor_file_status,assessment,assessment_items
          }
          Set-Property @SetParam
        }
      }
    }
    $Request
  }
}
function Get-FalconHostGroup {
<#
.SYNOPSIS
Search for host groups
.DESCRIPTION
Requires 'Host groups: Read'.
.PARAMETER Id
Host group identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/devices/queries/host-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get',Position=1)]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc',
      'group_type.asc','group_type.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc',
      'modified_timestamp.desc','name.asc','name.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get',Position=3)]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get',Position=4)]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get',Position=4)]
    [ValidateSet('members',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/host-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/devices/queries/host-groups/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    if ($Include) {
      Invoke-Falcon @Param -UserInput $PSBoundParameters | ForEach-Object {
        Add-Include $_ $PSBoundParameters @{ members = 'Get-FalconHostGroupMember' }
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconHostGroupMember {
<#
.SYNOPSIS
Search for host group members
.DESCRIPTION
Requires 'Host groups: Read'.
.PARAMETER Id
Host group identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
The maximum records to return
.PARAMETER Offset
The offset to start retrieving records from
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconHostGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/devices/queries/host-group-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get',Position=2)]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get',Position=3)]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get',Position=4)]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get',Position=4)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get')]
    [Parameter(ParameterSetName='/devices/combined/host-group-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/devices/queries/host-group-members/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Invoke-FalconHostAction {
<#
.SYNOPSIS
Perform actions on hosts
.DESCRIPTION
Requires 'Hosts: Write', plus related permission(s) for 'Include' selection(s).
.PARAMETER Name
Action to perform
.PARAMETER Include
Include additional properties
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconHostAction
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/devices-actions/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/devices-actions/v2:post',Mandatory,Position=1)]
    [ValidateSet('contain','detection_suppress','detection_unsuppress','hide_host','lift_containment',
      'lift_filesystem_containment_all','unhide_host',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/devices/entities/devices-actions/v2:post',Position=2)]
    [ValidateSet('agent_version','cid','external_ip','filesystem_containment_status','first_seen',
      'host_hidden_status','hostname','last_seen','local_ip','mac_address','os_build','os_version','platform_name',
      'product_type','product_type_desc','reduced_functionality_mode','serial_number','system_manufacturer',
      'system_product_name','tags',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/devices/entities/devices-actions/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Max = if ($PSBoundParameters.Name -match '_host$') { 100 } else { 500 }
    }
    if ($PSBoundParameters.Name) {
      $PSBoundParameters['action_name'] = $PSBoundParameters.Name
      [void]$PSBoundParameters.Remove('name')
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      if ($Include) {
        Invoke-Falcon @Param -UserInput $PSBoundParameters | ForEach-Object {
          Add-Include $_ $PSBoundParameters -Command 'Get-FalconHost'
        }
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Invoke-FalconHostGroupAction {
<#
.SYNOPSIS
Perform actions on host groups
.DESCRIPTION
Adds or removes hosts from host groups in batches of 500.

Requires 'Host groups: Write'.
.PARAMETER Name
Action to perform
.PARAMETER Id
Host group identifier
.PARAMETER HostId
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconHostGroupAction
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/host-group-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/host-group-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('add-hosts','remove-hosts',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/devices/entities/host-group-actions/v1:post',Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/devices/entities/host-group-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id','HostIds')]
    [string[]]$HostId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('action_name'); Body = @{ root = @('ids','action_parameters') }}
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($HostId) { @($HostId).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['ids'] = @($PSBoundParameters.Id)
      [void]$PSBoundParameters.Remove('HostId')
      for ($i=0;$i -lt $List.Count;$i+=500) {
        $IdString = (@($List[$i..($i+499)]).foreach{ "'$_'" }) -join ','
        $PSBoundParameters['action_parameters'] = @(@{ name = 'filter'; value = "(device_id:[$IdString])" })
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function New-FalconHostGroup {
<#
.SYNOPSIS
Create host groups
.DESCRIPTION
Requires 'Host groups: Write'.
.PARAMETER InputObject
One or more host groups to create in a single request
.PARAMETER GroupType
Host group type
.PARAMETER Name
Host group name
.PARAMETER Description
Host group description
.PARAMETER AssignmentRule
Assignment rule for 'dynamic' host groups
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/host-groups/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({ Confirm-Parameter $_ 'New-FalconHostGroup' '/devices/entities/host-groups/v1:post' })]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:post',Mandatory,Position=1)]
    [ValidateSet('dynamic','static','staticByID',IgnoreCase=$false)]
    [Alias('group_type')]
    [string]$GroupType,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:post',Mandatory,Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:post',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:post',Position=4)]
    [ValidateScript({
      if ($PSBoundParameters.GroupType -ne 'dynamic') {
        throw "'AssignmentRule' can only be used with GroupType 'dynamic'."
      } else {
        $true
      }
    })]
    [Alias('assignment_rule')]
    [string]$AssignmentRule
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/devices/entities/host-groups/v1:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined properties and remove empty values
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.resources
        if ($i.group_type -ne 'dynamic' -and $i.assignment_rule) {
          # Remove 'assignment_rule' when 'group_type' is not 'dynamic'
          [void]$i.PSObject.Properties.Remove('assignment_rule')
        }
        Remove-EmptyValue $i group_type,name
        $List.Add($i)
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 10
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format.Body = @{ root = @('resources') }
      for ($i=0;$i -lt $List.Count;$i+=10) {
        $PSBoundParameters['resources'] = @($List[$i..($i+9)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconGroupingTag {
<#
.SYNOPSIS
Remove FalconGroupingTags from hosts
.DESCRIPTION
Requires 'Hosts: Write'.
.PARAMETER Tag
FalconGroupingTag value ['FalconGroupingTags/<string>']
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconGroupingTag
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/devices/tags/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/devices/tags/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^FalconGroupingTags/.+$')]
    [ValidateScript({
      @($_).foreach{
        if ((Test-RegexValue $_) -eq 'tag') {
          $true
        } else {
          throw "Valid values include letters, numbers, hyphens, unscores and forward slashes. ['$_']"
        }
      }
    })]
    [Alias('Tags')]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/devices/entities/devices/tags/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('device_ids','device_id','ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $PSBoundParameters['action'] = 'remove'
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconHostGroup {
<#
.SYNOPSIS
Remove host groups
.DESCRIPTION
Requires 'Host groups: Write'.
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconHostGroup
#>
  [CmdletBinding(DefaultParameterSetName='/devices/entities/host-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/devices/entities/host-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
      [void]$PSBoundParameters.Remove('Id')
      for ($i=0;$i -lt $List.Count;$i+=10) {
        $PSBoundParameters['ids'] = @($List[$i..($i+9)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}

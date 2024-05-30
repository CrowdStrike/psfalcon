function Edit-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Modify Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER InputObject
One or more policies to modify in a single request
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Setting
Policy settings
.PARAMETER Default
Modify the default Windows Device Control policy
.PARAMETER Blocked
Custom notification for blocked events
.PARAMETER UseBlocked
Enable custom notification for blocked events
.PARAMETER Restricted
Custom notification for restricted events
.PARAMETER UseRestricted
Enable custom notification for restricted events
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'Edit-FalconDeviceControlPolicy' '/policy/entities/device-control/v1:patch'
    })]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:patch',Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:patch',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:patch',Position=4)]
    [Alias('settings')]
    [object]$Setting,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:patch',Mandatory)]
    [switch]$Default,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:patch',Position=1)]
    [string]$Blocked,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:patch',Position=2)]
    [boolean]$UseBlocked,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:patch',Position=3)]
    [string]$Restricted,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:patch',Position=4)]
    [boolean]$UseRestricted
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = if ($PSCmdlet.ParameterSetName -match 'default-device-control') {
        $PSCmdlet.ParameterSetName
      } else {
        '/policy/entities/device-control/v1:patch'
      }
    }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.resources
        if ($i.settings.classes.exceptions) {
          # Remove exception 'id' values from 'settings' object
          @($i.settings.classes.exceptions).Where({$_.id}).foreach{ [void]$_.PSObject.Properties.Remove('id') }
        }
        $List.Add($i)
      }
    } else {
      if ($PSCmdlet.ParameterSetName -match 'default-device-control') {
        $PSBoundParameters['custom_notifications'] = @{}
        @('Blocked','Restricted').foreach{
          $Property = @{}
          if ($PSBoundParameters.$_) {
            # Add 'Blocked' or 'Restricted' as 'custom_message' and remove from input
            $Property['custom_message'] = $PSBoundParameters.$_
            [void]$PSBoundParameters.Remove($_)
          }
          if ($null -ne $PSBoundParameters."Use$_") {
            # Add 'Use' or 'UseRestricted' as 'use_custom' and remove from input
            $Property['use_custom'] = $PSBoundParameters."Use$_"
            [void]$PSBoundParameters.Remove("Use$_")
          }
          if ($Property.custom_message -or $null -ne $Property.use_custom) {
            # Add under 'custom_notifications'
            $PSBoundParameters.custom_notifications[($_.ToLower(),'notification' -join '_')] = $Property
          }
        }
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('resources') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['resources'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Get-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Search for Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Read'.
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
.PARAMETER Default
Retrieve default Device Control policy, including notification content
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/device-control/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get',Position=1)]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc',
      'enabled.asc','enabled.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc',
      'modified_timestamp.desc','name.asc','name.desc','platform_name.asc','platform_name.desc',
      'precedence.asc','precedence.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get',Position=3)]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get',Position=4)]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=4)]
    [ValidateSet('members',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/entities/default-device-control/v1:get',Mandatory)]
    [switch]$Default,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/device-control/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get')]
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
        Add-Include $_ $PSBoundParameters @{ members = 'Get-FalconDeviceControlPolicyMember' }
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconDeviceControlPolicyMember {
<#
.SYNOPSIS
Search for members of Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDeviceControlPolicyMember
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/device-control-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get',Position=2)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get',Position=3)]
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get',Position=4)]
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get')]
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/device-control-members/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/device-control-members/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Invoke-FalconDeviceControlPolicyAction {
<#
.SYNOPSIS
Perform actions on Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconDeviceControlPolicyAction
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/device-control-actions/v1:post',Mandatory,
       Position=1)]
    [ValidateSet('add-host-group','disable','enable','remove-host-group',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/device-control-actions/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/device-control-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('action_name'); Body = @{ root = @('ids','action_parameters') }}
    }
  }
  process {
    $PSBoundParameters['ids'] = @($PSBoundParameters.Id)
    [void]$PSBoundParameters.Remove('Id')
    if ($PSBoundParameters.GroupId) {
      $PSBoundParameters['action_parameters'] = @(@{ name = 'group_id'; value = $PSBoundParameters.GroupId })
      [void]$PSBoundParameters.Remove('GroupId')
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function New-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Create Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER InputObject
One or more policies to create in a single request
.PARAMETER Name
Policy name
.PARAMETER PlatformName
Operating system platform
.PARAMETER Description
Policy description
.PARAMETER Settings
Hashtable of policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'New-FalconDeviceControlPolicy' '/policy/entities/device-control/v1:post'
    })]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:post',Mandatory,Position=2)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:post',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:post',Position=4)]
    [Alias('settings')]
    [object]$Setting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/device-control/v1:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.resources
        if ($i.settings.classes.exceptions) {
          # Remove exception 'id' values from 'settings' object
          @($i.settings.classes.exceptions).Where({$_.id}).foreach{ [void]$_.PSObject.Properties.Remove('id') }
        }
        $List.Add($i)
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('resources') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['resources'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Remove Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/device-control/v1:delete',Mandatory,
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
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconDeviceControlPrecedence {
<#
.SYNOPSIS
Set Falcon Device Control policy precedence
.DESCRIPTION
All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to define
policy precedence.

Requires 'Device control policies: Write'.
.PARAMETER PlatformName
Operating system platform
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconDeviceControlPrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control-precedence/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/device-control-precedence/v1:post',Mandatory,Position=1)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/policy/entities/device-control-precedence/v1:post',Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconDeviceControlClass {
<#
.SYNOPSIS
Modify Device Control policy classes
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER InputObject
One or more policy identifiers and class objects to modify in a single request
.PARAMETER BluetoothClass
Bluetooth class modifications and exceptions
.PARAMETER UsbClass
USB class modifications and exceptions
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDeviceControlClass
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control-classes/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'Edit-FalconDeviceControlClass' '/policy/entities/device-control-classes/v1:patch'
    })]
    [Alias('policies','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/device-control-classes/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/entities/device-control-classes/v1:patch',Position=2)]
    [Alias('bluetooth_classes')]
    [object]$BluetoothClass,
    [Parameter(ParameterSetName='/policy/entities/device-control-classes/v1:patch',Position=3)]
    [Alias('usb_classes')]
    [object]$UsbClass
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/policy/entities/device-control-classes/v1:patch'
    }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'policies' properties and remove empty values
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.policies
        Remove-EmptyValue $i
        $List.Add($i)
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Modify in groups of 100
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('policies') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['policies'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Edit-FalconDeviceControlNotification {
<#
.SYNOPSIS
Modify default Device Control notification settings
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER Bluetooth
Bluetooth custom notification settings ('blocked_notification')
.PARAMETER Usb
USB custom notification settings ('blocked_notification', 'restricted_notification')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDeviceControlNotification
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control-default-settings/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/device-control-default-settings/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('bluetooth_custom_notifications')]
    [object]$Bluetooth,
    [Parameter(ParameterSetName='/policy/entities/device-control-default-settings/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('usb_custom_notifications')]
    [object]$Usb
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('bluetooth_custom_notifications','usb_custom_notifications') }}
    }
  }
  process {
    @('Bluetooth','Usb').foreach{
      # Select required properties for 'bluetooth_custom_notifications' and 'usb_custom_notifications'
      [string[]]$Select = 'use_custom','custom_message'
      if ($_ -eq 'Bluetooth') {
        $PSBoundParameters.$_ = [PSCustomObject]$PSBoundParameters.$_ | Select-Object @{
          l='blocked_notification'
          e={[PSCustomObject]$_.blocked_notification | Select-Object $Select}
        }
      } else {
        $PSBoundParameters.$_ = [PSCustomObject]$PSBoundParameters.$_ | Select-Object @{
          l='blocked_notification'
          e={[PSCustomObject]$_.blocked_notification | Select-Object $Select}
        },
        @{
          l='restricted_notification'
          e={[PSCustomObject]$_.restricted_notification | Select-Object $Select}
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Edit-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Modify Falcon Device Control policies
.DESCRIPTION
Requires 'Device control policies: Write'.
.PARAMETER InputObject
One or more policies to modify in a single request
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER UsbSetting
USB settings
.PARAMETER BluetoothSetting
Bluetooth settings
.PARAMETER Propagated
Propagate policy to child environments
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'Edit-FalconDeviceControlPolicy' '/policy/entities/device-control/v2:patch'
    })]
    [Alias('policies','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Position=3)]
    [Alias('usb_settings')]
    [object]$UsbSetting,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Position=4)]
    [Alias('bluetooth_settings')]
    [object]$BluetoothSetting,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [boolean]$Propagated,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:patch',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/device-control/v2:patch' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'policies' properties and remove empty values
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.policies
        Remove-EmptyValue $i
        $List.Add($i)
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Modify in groups of 100
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('policies') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['policies'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Get-FalconDeviceControlNotification {
<#
.SYNOPSIS
List default Device Control notification settings
.DESCRIPTION
Requires 'Device control policies: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconDeviceControlNotification
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control-default-settings/v1:get',
    SupportsShouldProcess)]
  param()
  process {Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
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
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc',
      'enabled.asc','enabled.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc',
      'modified_timestamp.desc','name.asc','name.desc','platform_name.asc','platform_name.desc',
      'precedence.asc','precedence.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get',Position=4)]
    [ValidateSet('members',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/queries/device-control/v1:get')]
    [switch]$Detailed,
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
    [ValidateScript({Test-FqlStatement $_})]
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
.PARAMETER Name
Policy name
.PARAMETER PlatformName
Operating system platform
.PARAMETER Description
Policy description
.PARAMETER UsbSetting
USB settings [default values will be supplied if omitted]
.PARAMETER BluetoothSetting
Bluetooth settings [default values will be supplied if omitted]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconDeviceControlPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/device-control/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'New-FalconDeviceControlPolicy' '/policy/entities/device-control/v2:post'
    })]
    [Alias('policies','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:post',Mandatory,Position=2)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:post',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:post',Position=4)]
    [Alias('usb_settings')]
    [object]$UsbSetting,
    [Parameter(ParameterSetName='/policy/entities/device-control/v2:post',Position=5)]
    [Alias('bluetooth_settings')]
    [object]$BluetoothSetting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/device-control/v2:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      # Filter to defined 'policies' properties
      @($InputObject).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.policies)) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 100
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('policies') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['policies'] = @($List[$i..($i + 99)])
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
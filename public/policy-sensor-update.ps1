function Edit-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Modify Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Write'.
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
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconSensorUpdatePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'Edit-FalconSensorUpdatePolicy' '/policy/entities/sensor-update/v2:patch'
    })]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=4)]
    [Alias('settings')]
    [object]$Setting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/sensor-update/v2:patch' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.resources
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
function Get-FalconBuild {
<#
.SYNOPSIS
Retrieve Falcon Sensor builds for assignment in Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Read'.
.PARAMETER Platform
Operating system platform
.PARAMETER Stage
Sensor release stage
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconBuild
#>
  [CmdletBinding(DefaultParameterSetName='/policy/combined/sensor-update-builds/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/combined/sensor-update-builds/v1:get',Position=1)]
    [ValidateSet('linux','mac','windows',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-builds/v1:get',Position=2)]
    [ValidateSet('early_adopter','prod',IgnoreCase=$false)]
    [string[]]$Stage
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconKernel {
<#
.SYNOPSIS
Search for Falcon kernel compatibility information for Sensor builds
.DESCRIPTION
Requires 'Sensor update policies: Read'.
.PARAMETER Field
Return values for a specific field
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconKernel
#>
  [CmdletBinding(DefaultParameterSetName='/policy/combined/sensor-update-kernels/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get',Mandatory,
       Position=1)]
    [ValidateSet('architecture','base_package_supported_sensor_versions','distro','distro_version',
      'flavor','release','vendor','version','ztl_supported_sensor_versions',IgnoreCase=$false)]
    [string]$Field,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get',Position=1)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get',Position=2)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get',Position=3)]
    [ValidateSet('architecture.asc','architecture.desc','distro.asc','distro.desc','distro_version.asc',
      'distro_version.desc','flavor.asc','flavor.desc','release.asc','release.desc','vendor.asc',
      'vendor.desc','version.asc','version.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get',Position=4)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{distinct-field}/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = if ($PSBoundParameters.Field) {
        $PSCmdlet.ParameterSetName -replace '\{distinct-field\}',$PSBoundParameters.Field
        [void]$PSBoundParameters.Remove('Field')
      } else {
        $PSCmdlet.ParameterSetName
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Search for Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSensorUpdatePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/sensor-update/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get',Position=1)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc',
      'enabled.asc','enabled.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc',
      'modified_timestamp.desc','name.asc','name.desc','platform_name.asc','platform_name.desc',
      'precedence.asc','precedence.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get',Position=3)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:get',Position=2)]
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get',Position=4)]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get',Position=4)]
    [ValidateSet('members',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get')]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/sensor-update/v2:get')]
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/sensor-update/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = $List }
    if ($Include) {
      Invoke-Falcon @Param -UserInput $PSBoundParameters | ForEach-Object {
        Add-Include $_ $PSBoundParameters @{ members = 'Get-FalconSensorUpdatePolicyMember' }
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconSensorUpdatePolicyMember {
<#
.SYNOPSIS
Search for members of Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSensorUpdatePolicyMember
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/sensor-update-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',Position=2)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get',Position=3)]
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get',Position=4)]
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get')]
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconUninstallToken {
<#
.SYNOPSIS
Retrieve an uninstallation or maintenance token
.DESCRIPTION
Requires 'Sensor update policies: Write', plus related permission(s) for 'Include' selection(s).
.PARAMETER AuditMessage
Audit log comment
.PARAMETER Include
Include additional properties
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconUninstallToken
#>
  [CmdletBinding(DefaultParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Position=1)]
    [Alias('audit_message')]
    [string]$AuditMessage,
    [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Position=2)]
    [ValidateSet('agent_version','cid','external_ip','first_seen','hostname','last_seen','local_ip',
      'mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
      'serial_number','system_manufacturer','system_product_name','tags',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [Alias('device_id','DeviceId')]
    [ValidatePattern('^([a-fA-F0-9]{32}|MAINTENANCE)$')]
    [string]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $Request = @($List | Select-Object -Unique).foreach{
        $PSBoundParameters['Id'] = $_
        Invoke-Falcon @Param -UserInput $PSBoundParameters -EA 1
      }
      if ($Request -and $Include) {
        [string[]]$ReqProperty = @($Request[0].PSObject.Properties.Name).Where({ $_ -ne 'device_id' })
        foreach ($i in ($Request.device_id | Get-FalconHost -EA 0 | Select-Object @($Include + 'device_id'))) {
          @($ReqProperty).foreach{ Set-Property $i $_ @($Request).Where({ $_.device_id -eq $i.device_id }).$_ }
          $i
        }
      } else {
        $Request
      }
    }
  }
}
function Invoke-FalconSensorUpdatePolicyAction {
<#
.SYNOPSIS
Perform actions on Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Write'.
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconSensorUpdatePolicyAction
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('add-host-group','disable','enable','remove-host-group',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Mandatory,
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
function New-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Create Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Write'.
.PARAMETER InputObject
One or more policies to create in a single request
.PARAMETER PlatformName
Operating system platform
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Setting
Policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconSensorUpdatePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({
      Confirm-Parameter $_ 'New-FalconSensorUpdatePolicy' '/policy/entities/sensor-update/v2:post'
    })]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:post',Mandatory,Position=2)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:post',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:post',Position=4)]
    [Alias('settings')]
    [object]$Setting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/sensor-update/v2:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[object]]$List = @()
  }
  process {
    if ($InputObject) {
      @($InputObject).foreach{
        # Filter to defined 'resources' properties
        $i = [PSCustomObject]$_ | Select-Object $Param.Format.Body.resources
        if ($i.settings.scheduler -and $i.settings.scheduler.enabled -eq $false) {
          # Remove 'scheduler' if disabled
          [void]$i.settings.PSObject.Properties.Remove('scheduler')
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
function Remove-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Remove Sensor Update policies
.DESCRIPTION
Requires 'Sensor update policies: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSensorUpdatePolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sensor-update/v1:delete',Mandatory,
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
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Set-FalconSensorUpdatePrecedence {
<#
.SYNOPSIS
Set Sensor Update policy precedence
.DESCRIPTION
All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to define
policy precedence.

Requires 'Sensor update policies: Write'.
.PARAMETER PlatformName
Operating system platform
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconSensorUpdatePrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update-precedence/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/sensor-update-precedence/v1:post',Mandatory,Position=1)]
    [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
    [Alias('platform_name')]
    [string]$PlatformName,
    [Parameter(ParameterSetName='/policy/entities/sensor-update-precedence/v1:post',Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
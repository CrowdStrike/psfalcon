function Copy-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Device Control policy
.DESCRIPTION
The specified Falcon Device Control policy will be duplicated without assigned Host Groups. If a policy
description is not supplied, the description from the existing policy will be used.

Requires 'Device control policies: Read', 'Device control policies: Write'.
.PARAMETER Name
Name for the policy that will be created
.PARAMETER Description
Description for the policy that will be created
.PARAMETER Id
Identifier of policy to be copied
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Copy-FalconDeviceControlPolicy
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Description,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  process {
    if ($PSCmdlet.ShouldProcess('Copy-FalconDeviceControlPolicy','Get-FalconDeviceControlPolicy')) {
      try {
        $Policy = Get-FalconDeviceControlPolicy -Id $Id
        if ($Policy) {
          @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
          $Clone = $Policy | New-FalconDeviceControlPolicy
          if ($Clone.id) {
            @('usb_settings','bluetooth_settings').foreach{ $Clone.$_ = $Policy.$_ }
            $Clone = $Clone | Edit-FalconDeviceControlPolicy
            if ($Clone.enabled -eq $false -and $Policy.enabled -eq $true) {
              $Enable = $Clone.id | Invoke-FalconDeviceControlPolicyAction enable
              if ($Enable) {
                $Enable
              } else {
                $Clone.enabled = $true
                $Clone
              }
            }
          }
        }
      } catch {
        throw $_
      }
    }
  }
}
function Copy-FalconFirewallPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Firewall Management policy
.DESCRIPTION
The specified Falcon Firewall Management policy will be duplicated without assigned Host Groups. If a policy
description is not supplied, the description from the existing policy will be used.

Requires 'Firewall management: Read', 'Firewall management: Write'.
.PARAMETER Name
Name for the policy that will be created
.PARAMETER Description
Description for the policy that will be created
.PARAMETER Id
Identifier of policy to be copied
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Copy-FalconFirewallPolicy
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Description,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  process {
    if ($PSCmdlet.ShouldProcess('Copy-FalconFirewallPolicy','Get-FalconFirewallPolicy')) {
      try {
        $Policy = Get-FalconFirewallPolicy -Id $Id -Include settings
        if ($Policy) {
          @('Name','Description').foreach{
            if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }
          }
          if ($Policy) {
            $Clone = $Policy | New-FalconFirewallPolicy
            if ($Clone.id) {
              if ($Policy.settings) {
                $Policy.settings.policy_id = $Clone.id
                $Settings = $Policy.settings | Edit-FalconFirewallSetting
                if ($Settings) { $Settings = Get-FalconFirewallSetting -Id $Clone.id }
              }
              if ($Clone.enabled -eq $false -and $Policy.enabled -eq $true) {
                $Enable = $Clone.id | Invoke-FalconFirewallPolicyAction enable
                if ($Enable) {
                  Set-Property $Enable settings $Settings
                  $Enable
                } else {
                  $Clone.enabled = $true
                  Set-Property $Clone settings $Settings
                  $Clone
                }
              }
            }
          }
        }
      } catch {
        throw $_
      }
    }
  }
}
function Copy-FalconPreventionPolicy {
<#
.SYNOPSIS
Duplicate a Prevention policy
.DESCRIPTION
The specified Prevention policy will be duplicated without assigned Host Groups. If a policy description is not
supplied, the description from the existing policy will be used.

Requires 'Prevention Policies: Read', 'Prevention Policies: Write'.
.PARAMETER Name
Name for the policy that will be created
.PARAMETER Description
Description for the policy that will be created
.PARAMETER Id
Identifier of policy to be copied
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Copy-FalconPreventionPolicy
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Description,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  process {
    if ($PSCmdlet.ShouldProcess('Copy-FalconPreventionPolicy','Get-FalconPreventionPolicy')) {
      try {
        $Policy = Get-FalconPreventionPolicy -Id $Id
        if ($Policy) {
          @('Name','Description').foreach{
            if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }
          }
          $Clone = $Policy | New-FalconPreventionPolicy
          if ($Clone.id) {
            $Clone.prevention_settings = $Policy.prevention_settings
            $Clone = $Clone | Edit-FalconPreventionPolicy
            if ($Clone.enabled -eq $false -and $Policy.enabled -eq $true) {
              $Enable = $Clone.id | Invoke-FalconPreventionPolicyAction enable
              if ($Enable) {
                $Enable
              } else {
                $Clone.enabled = $true
                $Clone
              }
            }
          }
        }
      } catch {
        throw $_
      }
    }
  }
}
function Copy-FalconResponsePolicy {
<#
.SYNOPSIS
Duplicate a Real-time Response policy
.DESCRIPTION
The specified Real-time Response policy will be duplicated without assigned Host Groups. If a policy description
is not supplied, the description from the existing policy will be used.

Requires 'Response policies: Read', 'Response policies: Write'.
.PARAMETER Name
Name for the policy that will be created
.PARAMETER Description
Description for the policy that will be created
.PARAMETER Id
Identifier of policy to be copied
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Copy-FalconResponsePolicy
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Description,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  process {
    if ($PSCmdlet.ShouldProcess('Copy-FalconResponsePolicy','Get-FalconResponsePolicy')) {
      try {
        $Policy = Get-FalconResponsePolicy -Id $Id
        if ($Policy) {
          @('Name','Description').foreach{
            if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }
          }
          $Clone = $Policy | New-FalconResponsePolicy
          if ($Clone.id) {
            $Clone.settings = $Policy.settings
            $Clone = $Clone | Edit-FalconResponsePolicy
            if ($Clone.enabled -eq $false -and $Policy.enabled -eq $true) {
              $Enable = $Clone.id | Invoke-FalconResponsePolicyAction enable
              if ($Enable) {
                $Enable
              } else {
                $Clone.enabled = $true
                $Clone
              }
            }
          }
        }
      } catch {
        throw $_
      }
    }
  }
}
function Copy-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Duplicate a Sensor Update policy
.DESCRIPTION
The specified Sensor Update policy will be duplicated without assigned Host Groups. If a policy description is
not supplied, the description from the existing policy will be used.

Requires 'Sensor update policies: Read', 'Sensor update policies: Write'.
.PARAMETER Name
Name for the policy that will be created
.PARAMETER Description
Description for the policy that will be created
.PARAMETER Id
Identifier of policy to be copied
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Copy-FalconSensorUpdatePolicy
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$Name,
    [Parameter(Position=2)]
    [string]$Description,
    [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  process {
    if ($PSCmdlet.ShouldProcess('Copy-FalconSensorUpdatePolicy','Get-FalconSensorUpdatePolicy')) {
      try {
        $Policy = Get-FalconSensorUpdatePolicy -Id $Id
        if ($Policy) {
          @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
          $Clone = $Policy | New-FalconSensorUpdatePolicy
          if ($Clone.id) {
            $Clone.settings = $Policy.settings
            $Clone = $Clone | Edit-FalconSensorUpdatePolicy
            if ($Clone.enabled -eq $false -and $Policy.enabled -eq $true) {
              $Enable = $Clone.id | Invoke-FalconSensorUpdatePolicyAction enable
              if ($Enable) {
                $Enable
              } else {
                $Clone.enabled = $true
                $Clone
              }
            }
          }
        }
      } catch {
        throw $_
      }
    }
  }
}
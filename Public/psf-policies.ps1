function Copy-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Device Control policy
.DESCRIPTION
Requires 'Device Control Policies: Read', 'Device Control Policies: Write'.

The specified Falcon Device Control policy will be duplicated without assigned Host Groups. If a policy
description is not supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/USB-Device-Control-Policy
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [string]$Name,
        [Parameter(Position=2)]
        [string]$Description,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    process {
        try {
            $Policy = Get-FalconDeviceControlPolicy -Id $Id
            @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
            $Clone = $Policy | New-FalconDeviceControlPolicy
            if ($Clone.id) {
                $Clone.settings = $Policy.settings
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
        } catch {
            throw $_
        }
    }
}
function Copy-FalconFirewallPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Firewall Management policy
.DESCRIPTION
Requires 'Firewall Management: Read', 'Firewall Management: Write'.

The specified Falcon Firewall Management policy will be duplicated without assigned Host Groups. If a policy
description is not supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Firewall-Management
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [string]$Name,
        [Parameter(Position=2)]
        [string]$Description,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    process {
        try {
            $Policy = Get-FalconFirewallPolicy -Id $Id -Include settings
            @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
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
        } catch {
            throw $_
        }
    }
}
function Copy-FalconPreventionPolicy {
<#
.SYNOPSIS
Duplicate a Prevention policy
.DESCRIPTION
Requires 'Prevention Policies: Read', 'Prevention Policies: Write'.

The specified Prevention policy will be duplicated without assigned Host Groups. If a policy description is not
supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Detection-and-Prevention-Policies
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [string]$Name,
        [Parameter(Position=2)]
        [string]$Description,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    process {
        try {
            $Policy = Get-FalconPreventionPolicy -Id $Id
            @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
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
        } catch {
            throw $_
        }
    }
}
function Copy-FalconResponsePolicy {
<#
.SYNOPSIS
Duplicate a Real-time Response policy
.DESCRIPTION
Requires 'Response Policies: Read', 'Response Policies: Write'.

The specified Real-time Response policy will be duplicated without assigned Host Groups. If a policy description
is not supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Real-time-Response-Policy
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [string]$Name,
        [Parameter(Position=2)]
        [string]$Description,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    process {
        try {
            $Policy = Get-FalconResponsePolicy -Id $Id
            @('Name','Description').foreach{ if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }}
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
        } catch {
            throw $_
        }
    }
}
function Copy-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Duplicate a Sensor Update policy
.DESCRIPTION
Requires 'Sensor Update Policies: Read', 'Sensor Update Policies: Write'.

The specified Sensor Update policy will be duplicated without assigned Host Groups. If a policy description is
not supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK
https://github.com/CrowdStrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=1)]
        [string]$Name,
        [Parameter(Position=2)]
        [string]$Description,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    process {
        try {
            $Policy = Get-FalconSensorUpdatePolicy -Id $Id
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
        } catch {
            throw $_
        }
    }
}
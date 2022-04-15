function Copy-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Device Control policy
.DESCRIPTION
Requires 'device-control-policies:read','device-control-policies:write'.

The specified Falcon Device Control policy will be duplicated without assigned Host Groups. If a policy
description is not supplied, the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK

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
Requires 'firewall-management:read','firewall-management:write'.

The specified Falcon Firewall Management policy will be duplicated without assigned Host Groups. If a policy
description is not supplied,the description from the existing policy will be used.
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.LINK

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id,
        [Parameter(Mandatory,Position=2)]
        [string]$Name,
        [Parameter(Position=3)]
        [string]$Description
    )
    begin {
        $Policy = Get-FalconFirewallPolicy -Id $Id -EA 0
    }
    process {
        if (!$Policy) { throw "Policy '$Id' not found." }
        $Output = try {
            $Param = @{
                PlatformName = $Policy.platform_name
                Name = $PSBoundParameters.Name
                Description = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconFirewallPolicy @Param
            if ($Clone.id) {
                Get-FalconFirewallSetting -Id $Policy.id | Edit-FalconFirewallSetting -PolicyId $Clone.id
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    Invoke-FalconFirewallPolicyAction -Name enable -Id $Clone.id
                }
            }
        } catch {
            throw $_
        }
        <#
        $Output = if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } else { $Output }
        if ($Policy.settings -and !$Output.settings) {
            Get-FalconFirewallPolicy -Id $Output.id -Include settings
        } else {
            $Output
        }
        #>
    }
    end {
        $Output #if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } elseif ($Output) { $Output }
    }
}
function Copy-FalconPreventionPolicy {
<#
.SYNOPSIS
Duplicate a Prevention policy
.DESCRIPTION
Requires 'prevention-policies:read','prevention-policies:write'.

The specified Prevention policy will be duplicated without assigned Host Groups. If a policy description is not
supplied,the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK

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
Requires 'response-policies:read','response-policies:write'.

The specified Real-time Response policy will be duplicated without assigned Host Groups. If a policy description
is not supplied,the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK

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
Requires 'sensor-update-policies:read','sensor-update-policies:write'.

The specified Sensor Update policy will be duplicated without assigned Host Groups. If a policy description is
not supplied,the description from the existing policy will be used.
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Id
Policy identifier
.LINK

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
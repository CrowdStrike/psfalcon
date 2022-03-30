function Copy-FalconDeviceControlPolicy {
<#
.SYNOPSIS
Duplicate a Falcon Device Control policy
.DESCRIPTION
Requires 'device-control-policies:read','device-control-policies:write'.

The specified Falcon Device Control policy will be duplicated without assigned Host Groups. If a policy
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
    process {
        $Output = try {
            $Policy = Get-FalconDeviceControlPolicy -Id $Id
            $Settings = $Policy.settings
            if ($Settings.classes) {
                foreach ($Class in ($Settings.classes | Where-Object { $_.exceptions })) {
                    $Class.exceptions = @($Class.exceptions).foreach{
                        $_.PSObject.Properties.Remove('id')
                        $_
                    }
                }
            }
            $Param = @{
                PlatformName = $Policy.platform_name
                Name = $PSBoundParameters.Name
                Description = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconDeviceControlPolicy @Param
            if ($Clone.id) {
                Edit-FalconDeviceControlPolicy -Id $Clone.id -Settings $Settings
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id = $Clone.id
                    }
                    Invoke-FalconDeviceControlPolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } else { $Output }
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
    process {
        $Output = try {
            $Policy = Get-FalconPreventionPolicy -Id $Id
            $Settings = $Policy.prevention_settings.settings | Select-Object id,value
            $Param = @{
                PlatformName = $Policy.platform_name
                Name = $PSBoundParameters.Name
                Description = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconPreventionPolicy @Param
            if ($Clone.id) {
                Edit-FalconPreventionPolicy -Id $Clone.id -Settings $Settings
                if ($Policy.ioa_rule_groups) {
                    foreach ($GroupId in $Policy.ioa_rule_groups.id) {
                        $Param = @{
                            Name = 'add-rule-group'
                            Id = $Clone.id
                            GroupId = $GroupId
                        }
                        Invoke-FalconPreventionPolicyAction @Param
                    }
                }
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id = $Clone.id
                    }
                    Invoke-FalconPreventionPolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } else { $Output }
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
    process {
        $Output = try {
            $Policy = Get-FalconResponsePolicy -Id $Id
            $Settings = $Policy.settings.settings | Select-Object id,value
            $Param = @{
                PlatformName = $Policy.platform_name
                Name = $PSBoundParameters.Name
                Description = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconResponsePolicy @Param
            if ($Clone.id) {
                Edit-FalconResponsePolicy -Id $Clone.id -Settings $Settings
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id = $Clone.id
                    }
                    Invoke-FalconResponsePolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } else { $Output }
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
    process {
        $Output = try {
            $Policy = Get-FalconSensorUpdatePolicy -Id $Id
            $Param = @{
                PlatformName = $Policy.platform_name
                Name = $PSBoundParameters.Name
                Description = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconSensorUpdatePolicy @Param
            if ($Clone.id) {
                Edit-FalconSensorUpdatePolicy -Id $Clone.id -Settings $Policy.Settings
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id = $Clone.id
                    }
                    Invoke-FalconSensorUpdatePolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) { $Output[-1] } else { $Output }
    }
}
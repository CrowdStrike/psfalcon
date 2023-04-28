function Compare-FalconPreventionPhase {
<#
.SYNOPSIS
Compare a Falcon Prevention Policy against recommended implementation phases
.DESCRIPTION
Requires 'Prevention Policies: Read'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Compare-FalconPreventionPhase
#>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory,ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [string]$Id
    )
    begin {
        # Define allowed OSes and path to json settings
        [string[]]$AllowedOS = 'Linux','Mac','Windows'
        $List = [System.Collections.Generic.List[string]]@()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List -and $PSCmdlet.ShouldProcess('Compare-FalconPreventionPhase','Get-FalconPreventionPolicy')) {
            # Collect detailed policy information for unique identifiers
            $PolicyList = Get-FalconPreventionPolicy -Id ($List | Select-Object -Unique) -EA 0 | Select-Object id,
                name,platform_name,prevention_settings | Sort-Object platform_name
            @($List).Where({ $PolicyList.id -notcontains $_ }).foreach{
                # Generate error when 'id' values were not found
                Write-Error "'$_' was not found."
            }
            if ($PolicyList) {
                [string]$Ineligible = '[Compare-FalconPreventionPolicy] {0} is ineligible. [{1}]'
                if ($PolicyList.platform_name) {
                    # Import json settings for allowed 'platform_name' values
                    $Compare = @{}
                    [string]$JsonPath = Join-Path (Show-FalconModule).ModulePath policy
                    $PolicyList.platform_name | Select-Object -Unique | Where-Object { $AllowedOS -contains $_ } |
                    ForEach-Object {
                        [string]$FilePath = (Join-Path $JsonPath "$($_.ToLower()).json")
                        if (Test-Path $FilePath) {
                            $JsonValue = try { Get-Content $FilePath | ConvertFrom-Json } catch {}
                            if ($JsonValue) {
                                $Compare[$_] = $JsonValue
                            } else {
                                Write-Error "Failed to import $_ comparison template."
                            }
                        } else {
                            Write-Error "Failed to locate $_ comparison template. [$FilePath]"
                        }
                    }
                }
                if (!$Compare.Values) {
                    throw "No comparison templates were successfully imported."
                } else {
                    foreach ($Policy in $PolicyList) {
                        if ($AllowedOS -notcontains $Policy.platform_name) {
                            $PSCmdlet.WriteWarning(($Ineligible -f $Policy.id,$Policy.platform_name))
                        } elseif (!$Policy.prevention_settings) {
                            $PSCmdlet.WriteWarning(($Ineligible -f $Policy.id,'Missing prevention_settings'))
                        } elseif ($Compare.($Policy.platform_name)) {
                            # Filter to settings for eligible policies
                            [PSCustomObject[]]$Ref = $Compare.($Policy.platform_name)
                            foreach ($Category in $Policy.prevention_settings) {
                                foreach ($Setting in $Category.settings) {
                                    $Output = [PSCustomObject]@{
                                        policy_id = $Policy.id
                                        policy_name = $Policy.name
                                        platform_name = $Policy.platform_name
                                        category = $Category.name
                                        id = $Setting.id
                                        name = $Setting.name
                                        value = if ($Setting.type -eq 'toggle') {
                                            $Setting.value.enabled
                                        } elseif ($Setting.type -eq 'mlslider') {
                                            $Setting.value.PSObject.Properties.Value -join ':'
                                        }
                                    }
                                    foreach ($Phase in $Compare.($Policy.platform_name).phase) {
                                        # Include id and value for each phase
                                        ($Ref | Where-Object { $_.phase -eq $Phase }).prevention_settings |
                                        Where-Object { $_.id -eq $Setting.id } | ForEach-Object {
                                            $Value = if ($_.type -eq 'toggle') {
                                                 $_.value.enabled
                                            } elseif ($_.type -eq 'mlslider') {
                                                $_.value.PSObject.Properties.Value -join ':'
                                            }
                                            Set-Property $Output ('phase',$Phase -join '_') $Value
                                        }
                                    }
                                    Set-Property $Output 'description' $Setting.description
                                    $Output
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
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
                    @('Name','Description').foreach{
                        if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }
                    }
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
                    @('Name','Description').foreach{
                        if ($PSBoundParameters.$_) { $Policy.$_ = $PSBoundParameters.$_ }
                    }
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
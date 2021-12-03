function Copy-FalconDeviceControlPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(Position = 3)]
        [string] $Description
    )
    process {
        $Output = try {
            $Policy = Get-FalconDeviceControlPolicy -Ids $Id
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
                Name         = $PSBoundParameters.Name
                Description  = if ($PSBoundParameters.Description) {
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
                        Id   = $Clone.id
                    }
                    Invoke-FalconDeviceControlPolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) {
            $Output[-1]
        } else {
            $Output
        }
    }
}
function Copy-FalconFirewallPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(Position = 3)]
        [string] $Description
    )
    process {
        $Output = try {
            $Policy = Get-FalconFirewallPolicy -Ids $Id -Include settings
            $Param = @{
                PlatformName = $Policy.platform_name
                Name         = $PSBoundParameters.Name
                Description  = if ($PSBoundParameters.Description) {
                    $PSBoundParameters.Description
                } else {
                    $Policy.description
                }
            }
            $Clone = New-FalconFirewallPolicy @Param
            if ($Clone.id -and $Settings) {
                $Policy.settings | Edit-FalconFirewallSetting -PolicyId $Clone.id
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id   = $Clone.id
                    }
                    Invoke-FalconFirewallPolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
        $Output = if (($Output | Measure-Object).Count -gt 1) {
            $Output[-1]
        } else {
            $Output
        }
        if ($Policy.settings -and !$Output.settings) {
            Get-FalconFirewallPolicy -Ids $Output.id -Include settings
        } else {
            $Output
        }
    }
}
function Copy-FalconPreventionPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(Position = 3)]
        [string] $Description
    )
    process {
        $Output = try {
            $Policy = Get-FalconPreventionPolicy -Ids $Id
            $Settings = $Policy.prevention_settings.settings | Select-Object id, value
            $Param = @{
                PlatformName = $Policy.platform_name
                Name         = $PSBoundParameters.Name
                Description  = if ($PSBoundParameters.Description) {
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
                            Name    = 'add-rule-group'
                            Id      = $Clone.id
                            GroupId = $GroupId
                        }
                        Invoke-FalconPreventionPolicyAction @Param
                    }
                }
                if ($Policy.enabled -eq $true -and $Clone.enabled -eq $false) {
                    $Param = @{
                        Name = 'enable'
                        Id   = $Clone.id
                    }
                    Invoke-FalconPreventionPolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) {
            $Output[-1]
        } else {
            $Output
        }
    }
}
function Copy-FalconResponsePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(Position = 3)]
        [string] $Description
    )
    process {
        $Output = try {
            $Policy = Get-FalconResponsePolicy -Ids $Id
            $Settings = $Policy.settings.settings | Select-Object id, value
            $Param = @{
                PlatformName = $Policy.platform_name
                Name         = $PSBoundParameters.Name
                Description  = if ($PSBoundParameters.Description) {
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
                        Id   = $Clone.id
                    }
                    Invoke-FalconResponsePolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) {
            $Output[-1]
        } else {
            $Output
        }
    }
}
function Copy-FalconSensorUpdatePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidatePattern('^\w{32}$')]
        [string] $Id,

        [Parameter(Mandatory = $true, Position = 2)]
        [string] $Name,

        [Parameter(Position = 3)]
        [string] $Description
    )
    process {
        $Output = try {
            $Policy = Get-FalconSensorUpdatePolicy -Ids $Id
            $Param = @{
                PlatformName = $Policy.platform_name
                Name         = $PSBoundParameters.Name
                Description  = if ($PSBoundParameters.Description) {
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
                        Id   = $Clone.id
                    }
                    Invoke-FalconSensorUpdatePolicyAction @Param
                }
            }
        } catch {
            throw $_
        }
    }
    end {
        if (($Output | Measure-Object).Count -gt 1) {
            $Output[-1]
        } else {
            $Output
        }
    }
}
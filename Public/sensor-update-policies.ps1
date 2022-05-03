function Edit-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Modify Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Write'.
.PARAMETER Array
An array of policies to modify in a single request
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Setting
Policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v2:patch')]
    param(
        [Parameter(ParameterSetName='array',Mandatory,ValueFromPipeline)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'Edit-FalconSensorUpdatePolicy'
                    Endpoint = '/policy/entities/sensor-update/v2:patch'
                    Required = @('id')
                    Pattern = @('id')
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [object[]]$Array,
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Mandatory,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id,
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=2)]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=3)]
        [string]$Description,
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:patch',Position=4)]
        [Alias('settings')]
        [System.Object]$Setting
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/sensor-update/v2:patch'
            Format = @{
                Body = @{
                    resources = @('name','id','description','settings')
                    root = @('resources')
                }
            }
        }
        [System.Collections.Generic.List[object]]$List = @()
    }
    process {
        if ($Array) {
            @($Array).foreach{
                # Select allowed fields, when populated
                $i = $_
                [string[]]$Select = @('id','name','description','platform_name','settings').foreach{
                    if ($i.$_) { $_ }
                }
                $List.Add(($i | Select-Object $Select))
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            for ($i = 0; $i -lt $List.Count; $i += 100) {
                $PSBoundParameters['Array'] = @($List[$i..($i + 99)])
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Get-FalconBuild {
<#
.SYNOPSIS
Retrieve Falcon Sensor builds for assignment in Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Read'.
.PARAMETER Platform
Operating system platform
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/combined/sensor-update-builds/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/combined/sensor-update-builds/v1:get')]
        [ValidateSet('linux','mac','windows',IgnoreCase=$false)]
        [string]$Platform
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('platform') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconKernel {
<#
.SYNOPSIS
Search for Falcon kernel compatibility information for Sensor builds
.DESCRIPTION
Requires 'Sensor Update Policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get',Mandatory,
           Position=1)]
        [ValidateSet('architecture','base_package_supported_sensor_versions','distro','distro_version',
            'flavor','release','vendor','version','ztl_supported_sensor_versions',IgnoreCase=$false)]
        [string]$Field,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get',Position=1)]
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get',Position=2)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get',Position=2)]
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get',Position=3)]
        [ValidateSet('architecture.asc','architecture.desc','distro.asc','distro.desc','distro_version.asc',
            'distro_version.desc','flavor.asc','flavor.desc','release.asc','release.desc','vendor.asc',
            'vendor.desc','version.asc','version.desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get',Position=3)]
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get',Position=4)]
        [ValidateRange(1,5000)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
        [Parameter(ParameterSetName='/policy/queries/sensor-update-kernels/{field}/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/policy/combined/sensor-update-kernels/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = if ($PSBoundParameters.Field) {
                $PSCmdlet.ParameterSetName -replace '\{field\}',$PSBoundParameters.Field
                [void]$PSBoundParameters.Remove('Field')
            } else {
                $PSCmdlet.ParameterSetName
            }
            Format = @{ Query = @('offset','filter','sort','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Search for Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/sensor-update/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v2:get',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\w{32}$')]
        [Alias('Ids')]
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
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','ids','offset','filter','limit') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @($Id).foreach{ $List.Add($_) }
        } else {
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
        if ($Request -and $Include) {
            $Request = Add-Include $Request $PSBoundParameters @{ members = 'Get-FalconSensorUpdatePolicyMember' }
        }
        $Request
    }
}
function Get-FalconSensorUpdatePolicyMember {
<#
.SYNOPSIS
Search for members of Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/queries/sensor-update-members/v1:get')]
    param(
        [Parameter(ParameterSetName='/policy/queries/sensor-update-members/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [Parameter(ParameterSetName='/policy/combined/sensor-update-members/v1:get',ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{32}$')]
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
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('sort','offset','filter','id','limit') }
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
function Get-FalconUninstallToken {
<#
.SYNOPSIS
Retrieve an uninstallation or maintenance token
.DESCRIPTION
Requires 'Sensor Update Policies: Write', plus related permission(s) for 'Include' selection(s).
.PARAMETER AuditMessage
Audit log comment
.PARAMETER Include
Include additional properties
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/combined/reveal-uninstall-token/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Position=1)]
        [Alias('audit_message')]
        [string]$AuditMessage,
        [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Position=2)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','host_hidden_status','hostname',
            'last_seen','local_ip','mac_address','os_build','os_version','platform_name','product_type',
            'product_type_desc','reduced_functionality_mode','serial_number','system_manufacturer',
            'system_product_name','tags',IgnoreCase=$false)]
        [string[]]$Include,
        [Parameter(ParameterSetName='/policy/combined/reveal-uninstall-token/v1:post',Mandatory,
            ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
        [Alias('device_id','DeviceId')]
        [ValidatePattern('^(\w{32}|MAINTENANCE)$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('audit_message','device_id') }}
        }
    }
    process {
        foreach ($r in (Invoke-Falcon @Param -Inputs $PSBoundParameters)) {
            if ($Include) {
                # Append properties from 'Include'
                $i = Get-FalconHost -Id $r.device_id | Select-Object @($Include + 'device_id')
                foreach ($p in $Include) { Set-Property $r $p $i.$p }
            }
            $r
        }
    }
}
function Invoke-FalconSensorUpdatePolicyAction {
<#
.SYNOPSIS
Perform actions on Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Write'.
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update-actions/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Mandatory,Position=1)]
        [ValidateSet('add-host-group','disable','enable','remove-host-group',IgnoreCase=$false)]
        [Alias('action_name')]
        [string]$Name,
        [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Position=2)]
        [ValidatePattern('^\w{32}$')]
        [string]$GroupId,
        [Parameter(ParameterSetName='/policy/entities/sensor-update-actions/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=3)]
        [ValidatePattern('^\w{32}$')]
        [string]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{
                Query = @('action_name')
                Body = @{ root = @('ids','action_parameters') }
            }
        }
    }
    process {
        $PSBoundParameters['Ids'] = @($PSBoundParameters.Id)
        [void]$PSBoundParameters.Remove('Id')
        if ($PSBoundParameters.GroupId) {
            $PSBoundParameters['action_parameters'] = @(
                @{
                    name = 'group_id'
                    value = $PSBoundParameters.GroupId
                }
            )
            [void]$PSBoundParameters.Remove('GroupId')
        }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function New-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Create Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Write'.
.PARAMETER Array
An array of policies to create in a single request
.PARAMETER PlatformName
Operating system platform
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Setting
Policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v2:post')]
    param(
        [Parameter(ParameterSetName='array',Mandatory,ValueFromPipeline)]
        [ValidateScript({
            foreach ($Object in $_) {
                $Param = @{
                    Object = $Object
                    Command = 'New-FalconSensorUpdatePolicy'
                    Endpoint = '/policy/entities/sensor-update/v2:post'
                    Required = @('name','platform_name')
                    Content = @('platform_name')
                    Format = @{ platform_name = 'PlatformName' }
                }
                Confirm-Parameter @Param
            }
        })]
        [Alias('resources')]
        [object[]]$Array,
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
        [System.Object]$Setting
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = '/policy/entities/sensor-update/v2:post'
            Format = @{
                Body = @{
                    resources = @('description','platform_name','name','settings')
                    root =      @('resources')
                }
            }
        }
        [System.Collections.Generic.List[object]]$List = @()
    }
    process {
        if ($Array) {
            @($Array).foreach{
                # Select allowed fields, when populated
                $i = $_
                [string[]]$Select = @('name','description','platform_name','settings').foreach{ if ($i.$_) { $_ }}
                $List.Add(($i | Select-Object $Select))
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            for ($i = 0; $i -lt $List.Count; $i += 100) {
                $PSBoundParameters['Array'] = @($List[$i..($i + 99)])
                Invoke-Falcon @Param -Inputs $PSBoundParameters
            }
        }
    }
}
function Remove-FalconSensorUpdatePolicy {
<#
.SYNOPSIS
Remove Sensor Update policies
.DESCRIPTION
Requires 'Sensor Update Policies: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update/v1:delete')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sensor-update/v1:delete',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [ValidatePattern('^\w{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Set-FalconSensorUpdatePrecedence {
<#
.SYNOPSIS
Set Sensor Update policy precedence
.DESCRIPTION
Requires 'Sensor Update Policies: Write'.

All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to define
policy precedence.
.PARAMETER PlatformName
Operating system platform
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Sensor-Update-Policy
#>
    [CmdletBinding(DefaultParameterSetName='/policy/entities/sensor-update-precedence/v1:post')]
    param(
        [Parameter(ParameterSetName='/policy/entities/sensor-update-precedence/v1:post',Mandatory,Position=1)]
        [ValidateSet('Windows','Mac','Linux',IgnoreCase=$false)]
        [Alias('platform_name')]
        [string]$PlatformName,
        [Parameter(ParameterSetName='/policy/entities/sensor-update-precedence/v1:post',Mandatory,Position=2)]
        [ValidatePattern('^\w{32}$')]
        [Alias('Ids')]
        [string[]]$Id
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Body = @{ root = @('platform_name','ids') }}
        }
    }
    process { Invoke-Falcon @Param -Inputs $PSBoundParameters }
}
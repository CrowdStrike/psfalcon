function Add-FalconGroupingTag {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
    }
    process {
        $PSBoundParameters['action'] = 'add'
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconHost {
    [CmdletBinding(DefaultParameterSetName = '/devices/queries/devices-scroll/v1:get')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/v1:get', Mandatory = $true, Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/devices/login-history/v1:post', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/devices/combined/devices/network-address-history/v1:post',
            Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 1)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('agent_load_flags','agent_version','bios_manufacturer','bios_version',
            'config_id_base','config_id_build','config_id_platform','cpu_signature','device_id','external_ip',
            'first_seen','hostname','last_login_timestamp','last_seen','local_ip','local_ip.raw','mac_address',
            'machine_domain','major_version','minor_version','modified_timestamp','os_version','ou','platform_id',
            'platform_name','product_type_desc','reduced_functionality_mode','release_group','serial_number',
            'site_name','status','system_manufacturer','system_product_name')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 2)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 2)]
        [ValidateSet('device_id.asc','device_id.desc','agent_load_flags.asc','agent_load_flags.desc',
            'agent_version.asc','agent_version.desc','bios_manufacturer.asc','bios_manufacturer.desc',
            'bios_version.asc','bios_version.desc','config_id_base.asc','config_id_base.desc',
            'config_id_build.asc','config_id_build.desc','config_id_platform.asc','config_id_platform.desc',
            'cpu_signature.asc','cpu_signature.desc','external_ip.asc','external_ip.desc','first_seen.asc',
            'first_seen.desc','hostname.asc','hostname.desc','last_login_timestamp.asc',
            'last_login_timestamp.desc','last_seen.asc','last_seen.desc','local_ip.asc','local_ip.desc',
            'local_ip.raw.asc','local_ip.raw.desc','mac_address.asc','mac_address.desc','machine_domain.asc',
            'machine_domain.desc','major_version.asc','major_version.desc','minor_version.asc',
            'minor_version.desc','modified_timestamp.asc','modified_timestamp.desc','os_version.asc',
            'os_version.desc','ou.asc','ou.desc','platform_id.asc','platform_id.desc','platform_name.asc',
            'platform_name.desc','product_type_desc.asc','product_type_desc.desc','reduced_functionality_mode.asc',
            'reduced_functionality_mode.desc','release_group.asc','release_group.desc','serial_number.asc',
            'serial_number.desc','site_name.asc','site_name.desc','status.asc','status.desc',
            'system_manufacturer.asc','system_manufacturer.desc','system_product_name.asc',
            'system_product_name.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 3)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 4)]
        [string] $Offset,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Position = 5)]
        [ValidateSet('login_history', 'network_history', 'zero_trust_assessment')]
        [array] $Include,

        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get', Mandatory = $true)]
        [switch] $Hidden,
        
        [Parameter(ParameterSetName = '/devices/combined/devices/login-history/v1:post', Mandatory = $true)]
        [switch] $Login,

        [Parameter(ParameterSetName = '/devices/combined/devices/network-address-history/v1:post',
            Mandatory = $true)]
        [switch] $Network,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/devices/queries/devices-scroll/v1:get')]
        [Parameter(ParameterSetName = '/devices/queries/devices-hidden/v1:get')]
        [switch] $Total
    )
    begin {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
        }
    }
    process {
        $Param['Format'] = if ($Param.Endpoint -match 'post$') {
            @{ Body = @{ root = @('ids') }}
        } else {
            @{ Query = @('ids', 'filter', 'sort', 'limit', 'offset') }
        }
        $Result = Invoke-Falcon @Param
        if ($PSBoundParameters.Include -and $Result) {
            if (!$Result.device_id) {
                $Result = @($Result).foreach{
                    ,[PSCustomObject] @{ device_id = $_ }
                }
            }
            if ($PSBoundParameters.Include -contains 'login_history') {
                foreach ($Item in (& $MyInvocation.MyCommand.Name -Ids $Result.device_id -Login)) {
                    $AddParam = @{
                        Object = $Result | Where-Object { $_.device_id -eq $Item.device_id }
                        Name   = 'login_history'
                        Value  = $Item.recent_logins
                    }
                    Add-Property @AddParam
                }
            }
            if ($PSBoundParameters.Include -contains 'network_history') {
                foreach ($Item in (& $MyInvocation.MyCommand.Name -Ids $Result.device_id -Network)) {
                    $AddParam = @{
                        Object = $Result | Where-Object { $_.device_id -eq $Item.device_id }
                        Name   = 'network_history'
                        Value  = $Item.history
                    }
                    Add-Property @AddParam
                }
            }
            if ($PSBoundParameters.Include -contains 'zero_trust_assessment') {
                foreach ($Item in (& Get-FalconZta -Ids $Result.device_id)) {
                    $AddParam = @{
                        Object = $Result | Where-Object { $_.device_id -eq $Item.device_id }
                        Name   = 'zero_trust_assessment'
                        Value  = $Item | Select-Object modified_time, sensor_file_status,
                            assessment, assessment_items
                    }
                    Add-Property @AddParam
                }
            }
        }
        $Result
    }
}
function Invoke-FalconHostAction {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices-actions/v2:post')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 1)]
        [ValidateSet('contain', 'lift_containment', 'hide_host', 'unhide_host')]
        [string] $Name,

        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Mandatory = $true,
            Position = 2)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices-actions/v2:post', Position = 3)]
        [ValidateSet('agent_version','cid','external_ip','first_seen','host_hidden_status','hostname','last_seen',
            'local_ip','mac_address','os_build','os_version','platform_name','product_type','product_type_desc',
            'reduced_functionality_mode','serial_number','system_manufacturer','system_product_name','tags')]
        [array] $Include
    )
    begin {
        $Fields = @{
            Name = 'action_name'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('action_name')
                Body  = @{
                    root = @('ids')
                }
            }
        }
        $Param['Max'] = if ($Param.Inputs.action_name -match 'host$') {
            100
        } else {
            500
        }
        $Result = Invoke-Falcon @Param
        if ($PSBoundParameters.Include -and $Result) {
            foreach ($Item in (Get-FalconHost -Ids $Result.id | Select-Object @($PSBoundParameters.Include +
            'device_id'))) {
                @($Item.PSObject.Properties.Where({ $_.Name -ne 'device_id' })).foreach{
                    $AddParam = @{
                        Object = $Result | Where-Object { $_.id -eq $Item.device_id }
                        Name   = $_.Name
                        Value  = $_.Value
                    }
                    Add-Property @AddParam
                }
            }
        }
        $Result
    }
}
function Remove-FalconGroupingTag {
    [CmdletBinding(DefaultParameterSetName = '/devices/entities/devices/tags/v1:patch')]
    param(
        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/devices/entities/devices/tags/v1:patch', Mandatory = $true, Position = 2)]
        [ValidatePattern('^FalconGroupingTags/\w{1,237}$')]
        [array] $Tags
    )
    begin {
        $Fields = @{
            Ids = 'device_ids'
        }
    }
    process {
        $PSBoundParameters['action'] = 'remove'
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('tags', 'device_ids', 'action')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
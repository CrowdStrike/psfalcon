function Get-FalconAsset {
    [CmdletBinding(DefaultParameterSetName = '/discover/queries/hosts/v1:get')]
    param(
        [Parameter(ParameterSetName = '/discover/entities/hosts/v1:get', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\w{32}_\w+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('agent_version','aid','bios_manufacturer','bios_version','cid','city',
            'confidence','country','current_local_ip','discoverer_aids','discoverer_count',
            'discoverer_platform_names','discoverer_product_type_descs','discoverer_tags','entity_type',
            'external_ip','first_discoverer_aid','first_discoverer_ip','first_seen_timestamp','groups',
            'hostname','id','kernel_version','last_discoverer_aid','last_seen_timestamp','local_ips_count',
            'machine_domain','network_interfaces','network_interfaces.interface_alias',
            'network_interfaces.interface_description','network_interfaces.local_ip',
            'network_interfaces.mac_address','network_interfaces.network_prefix','os_version','ou',
            'platform_name','product_type','product_type_desc','site_name','system_manufacturer',
            'system_product_name','system_serial_number','tags')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 2)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 3)]
        [ValidateRange(1,100)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get', Position = 4)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/discover/queries/hosts/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('filter', 'q', 'sort', 'limit', 'offset', 'ids')
            }
            Max      = 100
        }
        Invoke-Falcon @Param
    }
}
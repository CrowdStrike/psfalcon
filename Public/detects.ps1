function Edit-FalconDetection {
    [CmdletBinding(DefaultParameterSetName =  '/detects/entities/detects/v2:patch')]
    param(
        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Mandatory = $true, Position = 1)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 2)]
        [ValidateSet('new', 'in_progress', 'true_positive', 'false_positive', 'ignored', 'closed', 'reopened')]
        [string] $Status,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 3)]
        [ValidatePattern('^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$')]
        [string] $AssignedToUuid,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 4)]
        [string] $Comment,

        [Parameter(ParameterSetName = '/detects/entities/detects/v2:patch', Position = 5)]
        [boolean] $ShowInUi
    )
    begin {
        $Fields = @{
            AssignedToUuid = 'assigned_to_uuid'
            ShowInUi       = 'show_in_ui'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Body = @{
                    root = @('show_in_ui', 'comment', 'assigned_to_uuid', 'status', 'ids')
                }
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconDetection {
    [CmdletBinding(DefaultParameterSetName = '/detects/queries/detects/v1:get')]
    param(
        [Parameter(ParameterSetName = '/detects/entities/summaries/GET/v1:post', Mandatory = $true, Position = 1)]
        [ValidatePattern('^ldt:\w{32}:\d+$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('q','date_updated','assigned_to_name','max_confidence','detection_id',
            'max_severity','max_severity_displayname','seconds_to_triaged','seconds_to_resolved','status',
            'adversary_ids','cid','first_behavior','last_behavior','behaviors.parent_details.parent_md5',
            'behaviors.parent_details.parent_process_graph_id','behaviors.parent_details.parent_cmdline',
            'behaviors.parent_details.parent_sha256','behaviors.parent_details.parent_process_id',
            'behaviors.confidence','behaviors.severity','behaviors.triggering_process_id','behaviors.filename',
            'behaviors.sha256','behaviors.user_name','behaviors.user_id','behaviors.behavior_id',
            'behaviors.timestamp','behaviors.alleged_filetype','behaviors.control_graph_id','behaviors.md5',
            'behaviors.objective','behaviors.tactic','behaviors.technique','behaviors.pattern_disposition',
            'behaviors.cmdline','behaviors.triggering_process_graph_id','behaviors.ioc_type',
            'behaviors.ioc_source','behaviors.ioc_value','behaviors.device_id','device.first_seen',
            'device.last_seen','device.modified_timestamp','device.site_name','device.config_id_platform',
            'device.system_manufacturer','device.bios_manufacturer','device.platform_name','device.hostname',
            'device.config_id_build','device.os_version','device.bios_version','device.agent_load_flags',
            'device.release_group','device.status','device.product_type_desc','device.machine_domain',
            'device.agent_local_time','device.device_id','device.system_product_name','device.product_type',
            'device.cid','device.external_ip','device.major_version','device.minor_version','device.platform_id',
            'device.config_id_base','device.ou','device.agent_version','device.local_ip','device.mac_address',
            'device.cpu_signature','device.reduced_functionality_mode','device.serial_number','hostinfo.domain',
            'hostinfo.active_directory_dn_display','quarantined_files.paths','quarantined_files.state',
            'quarantined_files.sha256','quarantined_files.id')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 2)]
        [string] $Query,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 3)]
        [string] $Sort,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get', Position = 5)]
        [int] $Offset,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/detects/queries/detects/v1:get')]
        [switch] $Total
    )
    begin {
        $Fields = @{
            Query = 'q'
        }
    }
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = Update-FieldName -Fields $Fields -Inputs $PSBoundParameters
            Format   = @{
                Query = @('filter', 'q', 'sort', 'limit', 'offset')
                Body  = @{
                    root = @('ids')
                }
            }
            Max      = 1000
        }
        Invoke-Falcon @Param
    }
}
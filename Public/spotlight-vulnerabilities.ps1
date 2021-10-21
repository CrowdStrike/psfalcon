function Get-FalconRemediation {
    [CmdletBinding(DefaultParameterSetName = '/spotlight/entities/remediations/v2:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/remediations/v2:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}$')]
        [array] $Ids
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('ids')
            }
        }
        Invoke-Falcon @Param
    }
}
function Get-FalconVulnerability {
    [CmdletBinding(DefaultParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
    param(
        [Parameter(ParameterSetName = '/spotlight/entities/vulnerabilities/v2:get', Mandatory = $true,
            Position = 1)]
        [ValidatePattern('^\w{32}_\w{32}$')]
        [array] $Ids,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Mandatory = $true,
            Position = 1)]
        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Mandatory = $true,
            Position = 1)]
        [ValidateScript({
            Test-FqlStatement $_ @('aid', 'apps_remediation', 'closed_timestamp', 'created_timestamp',
                'cve.exploit_status', 'cve.exprt_rating', 'cve.id', 'cve.severity', 'host_info.groups',
                'host_info.platform_name', 'host_info.product_type_desc', 'host_info.tags',
                'host_last_seen_timestamp', 'status', 'updated_timestamp')
        })]
        [string] $Filter,

        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Position = 2)]
        [ValidateSet('cve', 'host_info', 'remediation')]
        [array] $Facet,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 3)]
        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Position = 3)]
        [ValidateSet('created_timestamp.asc','created_timestamp.desc','closed_timestamp.asc',
            'closed_timestamp.desc','updated_timestamp.asc','updated_timestamp.desc')]
        [string] $Sort,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 4)]
        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Position = 4)]
        [ValidateRange(1,5000)]
        [int] $Limit,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get', Position = 5)]
        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Position = 5)]
        [string] $After,

        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get', Mandatory = $true)]
        [switch] $Detailed,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [Parameter(ParameterSetName = '/spotlight/combined/vulnerabilities/v1:get')]
        [switch] $All,

        [Parameter(ParameterSetName = '/spotlight/queries/vulnerabilities/v1:get')]
        [switch] $Total
    )
    process {
        $Param = @{
            Command  = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Inputs   = $PSBoundParameters
            Format   = @{
                Query = @('after', 'sort', 'ids', 'filter', 'limit', 'facet')
            }
        }
        Invoke-Falcon @Param
    }
}
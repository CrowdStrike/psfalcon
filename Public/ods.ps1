function Get-FalconScan {
<#
.SYNOPSIS
Search for on-demand or scheduled scan results
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Scan result identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScan
#>
    [CmdletBinding(DefaultParameterSetName='/ods/queries/scans/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ods/entities/scans/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get',Position=2)]
        [ValidateSet('id|asc','id|desc','initiated_from|asc','initiated_from|desc','description.keyword|asc',
            'description.keyword|desc','filecount.scanned|asc','filecount.scanned|desc','filecount.malicious|asc',
            'filecount.malicious|desc','filecount.quarantined|asc','filecount.quarantined|desc',
            'filecount.skipped|asc','filecount.skipped|desc','affected_hosts_count|asc',
            'affected_hosts_count|desc','status|asc','status|desc','severity|asc','severity|desc',
            'scan_started_on|asc','scan_started_on|desc','scan_completed_on|asc','scan_completed_on|desc',
            'created_on|asc','created_on|desc','created_by|asc','created_by|desc','last_updated|asc',
            'last_updated|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get',Position=3)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ods/queries/scans/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('offset','limit','sort','filter','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconScanFile {
<#
.SYNOPSIS
Search for files found by on-demand or scheduled scans
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Malicious file identifier from a scan result
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScanFile
#>
    [CmdletBinding(DefaultParameterSetName='/ods/queries/malicious-files/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ods/entities/malicious-files/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=2)]
        [ValidateSet('id|asc','id|desc','scan_id|asc','scan_id|desc','host_id|asc','host_id|desc',
            'host_scan_id|asc','host_scan_id|desc','filename|asc','filename|desc','hash|asc','hash|desc',
            'pattern_id|asc','pattern_id|desc','severity|asc','severity|desc','last_updated|asc',
            'last_updated|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=3)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('offset','limit','sort','filter','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
function Get-FalconScanHost {
<#
.SYNOPSIS
Search for on-demand or scheduled scan metadata for specific hosts
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Scanned host metadata identifier from a scan result
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScanHost
#>
    [CmdletBinding(DefaultParameterSetName='/ods/queries/scan-hosts/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ods/entities/scan-hosts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [Alias('ids')]
        [object[]]$Id,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get',Position=2)]
        [ValidateSet('id|asc','id|desc','scan_id|asc','scan_id|desc','host_id|asc','host_id|desc',
            'filecount.scanned|asc','filecount.scanned|desc','filecount.malicious|asc','filecount.malicious|desc',
            'filecount.quarantined|asc','filecount.quarantined|desc','filecount.skipped|asc',
            'filecount.skipped|desc','status|asc','status|desc','severity|asc','severity|desc','started_on|asc',
            'started_on|desc','completed_on|asc','completed_on|desc','last_updated|asc','last_updated|desc',
            IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get',Position=3)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('offset','limit','sort','filter','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process {
        if ($Id) {
            @(Select-Property $Id Id '^[a-fA-F0-9]{32}$' $Param.Command scan_host_metadata_id metadata).foreach{
                if ($_ -is [string]) { $List.Add($_) } else { $PSCmdlet.WriteError($_) }
            }
        } else {
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
    end {
        if ($List) {
            $PSBoundParameters['Id'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}
function Get-FalconScheduledScan {
<#
.SYNOPSIS
Search for scheduled scans
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Scheduled scan identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScheduledScan
#>
    [CmdletBinding(DefaultParameterSetName='/ods/queries/scheduled-scans/v1:get',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:get',Mandatory,
            ValueFromPipelineByPropertyName,ValueFromPipeline)]
        [ValidatePattern('^[a-fA-F0-9]{32}$')]
        [Alias('ids')]
        [string[]]$Id,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get',Position=1)]
        [ValidateScript({ Test-FqlStatement $_ })]
        [string]$Filter,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get',Position=2)]
        [ValidateSet('id|asc','id|desc','description.keyword|asc','description.keyword|desc','status|asc',
            'status|desc','schedule.start_timestamp|asc','schedule.start_timestamp|desc','schedule.interval|asc',
            'schedule.interval|desc','created_on|asc','created_on|desc','created_by|asc','created_by|desc',
            'last_updated|asc','last_updated|desc',IgnoreCase=$false)]
        [string]$Sort,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get',Position=3)]
        [int32]$Limit,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get')]
        [int32]$Offset,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get')]
        [switch]$Detailed,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get')]
        [switch]$All,
        [Parameter(ParameterSetName='/ods/queries/scheduled-scans/v1:get')]
        [switch]$Total
    )
    begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('offset','limit','sort','filter','ids') }
        }
        [System.Collections.Generic.List[string]]$List = @()
    }
    process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
    end {
        if ($List) { $PSBoundParameters['Id'] = @($List | Select-Object -Unique) }
        Invoke-Falcon @Param -Inputs $PSBoundParameters
    }
}
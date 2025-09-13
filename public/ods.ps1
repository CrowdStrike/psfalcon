function Set-ScanInteger ([object]$Object) {
  @('SensorDetection','SensorPrevention','CloudDetection','CloudPrevention','CloudPupDetection',
  'CloudPupPrevention').foreach{
    if ($Object.$_) {
      [int]$Object.$_ = switch ($Object.$_) {
        # Change machine-learning levels to integer value
        'disabled' { 0 }
        'cautious' { 1 }
        'moderate' { 2 }
        'aggressive' { 3 }
        'extra_aggressive' { 4 }
      }
    }
  }
  if ($Object.CpuPriority) {
    [int]$Object.CpuPriority = switch ($Object.CpuPriority) {
      # Change CPU priority level to integer value
      'up_to_1' { 1 }
      'up_to_25' { 2 }
      'up_to_50' { 3 }
      'up_to_75' { 4 }
      'up_to_100' { 5 }
    }
  }
  if ($Object.Repeat) {
    [int]$Object.Repeat = switch ($Object.Repeat) {
      # Change interval to integer value
      'never' { 0 }
      'daily' { 1 }
      'weekly' { 7 }
      'every_other_week' { 14 }
      'every_4_weeks' { 28 }
      'monthly' { 30 }
    }
  }
  $Object
}
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
.PARAMETER Include
Include additional properties
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
    [Parameter(ParameterSetName='/ods/entities/scans/v2:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/ods/queries/scans/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
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
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/ods/queries/scans/v1:get',Position=4)]
    [ValidateSet('scan_file',IgnoreCase=$false)]
    [string[]]$Include,
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    } elseif ($Include -and $Include -contains 'scan_file') {
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
      @($Request).foreach{
        if ($_.id) {
          if ($_.filecount.malicious -or $_.filecount.quarantined) {
            # Append 'scan_file' when 'malicious' or 'quarantined' values are present under 'filecount'
            Set-Property $_ scan_file @(Get-FalconScanFile -ScanId $_.id -Detailed -All -EA 0)
          }
          $_
        } else {
          # Check for 'scan_file' for all identifiers when not returning 'Detailed' result
          [PSCustomObject]@{ id = $_; scan_file = @(Get-FalconScanFile -ScanId $_ -All -EA 0) }
        }
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconScanFile {
<#
.SYNOPSIS
Search for files found by on-demand or scheduled scans
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Malicious file identifier
.PARAMETER ScanId
On-demand scan identifier
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
    [Parameter(ParameterSetName='filter_by_scan_id',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$ScanId,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=2)]
    [Parameter(ParameterSetName='filter_by_scan_id')]
    [ValidateSet('id|asc','id|desc','scan_id|asc','scan_id|desc','host_id|asc','host_id|desc',
      'host_scan_id|asc','host_scan_id|desc','filename|asc','filename|desc','hash|asc','hash|desc',
      'pattern_id|asc','pattern_id|desc','severity|asc','severity|desc','last_updated|asc',
      'last_updated|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get',Position=3)]
    [Parameter(ParameterSetName='filter_by_scan_id')]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
    [Parameter(ParameterSetName='filter_by_scan_id')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
    [Parameter(ParameterSetName='filter_by_scan_id')]
    [switch]$All,
    [Parameter(ParameterSetName='/ods/queries/malicious-files/v1:get')]
    [Parameter(ParameterSetName='filter_by_scan_id')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = if ($PSCmdlet.ParameterSetName -eq 'filter_by_scan_id') {
        '/ods/queries/malicious-files/v1:get'
      } else {
        $PSCmdlet.ParameterSetName
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } else {
      if ($ScanId) { $PSBoundParameters['Filter'] = "scan_id:'$ScanId'" }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconScanHost {
<#
.SYNOPSIS
Search for on-demand or scheduled scan metadata for specific hosts
.DESCRIPTION
Requires 'On-demand scans (ODS): Read'.
.PARAMETER Id
Scanned host metadata identifier
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
    [Alias('ids','scan_host_metadata_id')]
    [object[]]$Id,
    [Parameter(ParameterSetName='/ods/queries/scan-hosts/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @(Select-Property $Id Id '^[a-fA-F0-9]{32}$' $Param.Command scan_host_metadata_id metadata).foreach{
        if ($_ -is [string]) { $List.Add($_) } else { $PSCmdlet.WriteError($_) }
      }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
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
    [ValidateScript({Test-FqlStatement $_})]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconScheduledScan {
<#
.SYNOPSIS
Create a scheduled scan targeting host groups
.DESCRIPTION
Requires 'On-demand scans (ODS): Write'.
.PARAMETER StartTime
Start time (yyyy-MM-ddThh:mm)
.PARAMETER Repeat
Repetition frequency
.PARAMETER FilePath
File path(s) to scan
.PARAMETER SensorDetection
On-sensor machine-learning detection level
.PARAMETER SensorPrevention
On-sensor machine-learning prevention level
.PARAMETER CloudDetection
Cloud-based machine-learning detection level
.PARAMETER CloudPrevention
Cloud-based machine-learning prevention level
.PARAMETER CloudPupDetection
Cloud-based machine-learning PUP detection level
.PARAMETER CloudPupPrevention
Cloud-based machine-learning PUP prevention level
.PARAMETER CpuPriority
Maximum CPU utilization
.PARAMETER ScanExclusion
File path(s) to exclude, in glob syntax
.PARAMETER ScanInclusion
File path(s) to include, in glob syntax
.PARAMETER Quarantine
Quarantine malicious files
.PARAMETER MaxFileSize
Maximum file size, in MB
.PARAMETER Notification
Show notification to end user
.PARAMETER MaxDuration
Allowable scan duration, in hours
.PARAMETER PauseDuration
Allowable pause duration, in hours
.PARAMETER Description
On-demand scan description
.PARAMETER Id
Host group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconScheduledScan
#>
  [CmdletBinding(DefaultParameterSetName='/ods/entities/scheduled-scans/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=1)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$')]
    [string]$StartTime,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=2)]
    [ValidateSet('never','daily','weekly','every_other_week','every_4_weeks','monthly',IgnoreCase=$false)]
    [string]$Repeat,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=3)]
    [Alias('file_paths')]
    [string[]]$FilePath,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=4)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('sensor_ml_level_detection')]
    [string]$SensorDetection,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=5)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('sensor_ml_level_prevention')]
    [string]$SensorPrevention,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=6)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_ml_level_detection')]
    [string]$CloudDetection,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=7)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_ml_level_prevention')]
    [string]$CloudPrevention,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=8)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_pup_adware_level_detection')]
    [string]$CloudPupDetection,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=9)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_pup_adware_level_prevention')]
    [string]$CloudPupPrevention,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,Position=10)]
    [ValidateSet('up_to_1','up_to_25','up_to_50','up_to_75','up_to_100',IgnoreCase=$false)]
    [Alias('cpu_priority')]
    [string]$CpuPriority,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=11)]
    [Alias('scan_exclusions')]
    [string[]]$ScanExclusion,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=12)]
    [Alias('scan_inclusions')]
    [string[]]$ScanInclusion,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=13)]
    [boolean]$Quarantine,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=14)]
    [Alias('max_file_size')]
    [int32]$MaxFileSize,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=15)]
    [Alias('endpoint_notification')]
    [boolean]$Notification,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=16)]
    [Alias('max_duration')]
    [ValidateRange(0,24)]
    [int]$MaxDuration,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=17)]
    [Alias('pause_duration')]
    [ValidateRange(0,24)]
    [int]$PauseDuration,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Position=18)]
    [string]$Description,
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('host_groups')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      $UserInput = Set-ScanInteger $PSBoundParameters
      $UserInput['Schedule'] = @{ start_timestamp = $UserInput.StartTime; interval = $UserInput.Repeat }
      @('StartTime','Repeat').foreach{ [void]$UserInput.Remove($_) }
      $Param.Format.body.root += 'schedule'
      [void]$Param.Format.body.Remove('schedule')
      Invoke-Falcon @Param -UserInput $UserInput
    }
  }
}
function Remove-FalconScheduledScan {
<#
.SYNOPSIS
Remove a scheduled scan
.DESCRIPTION
Requires 'On-demand scans (ODS): Write'.
.PARAMETER Id
Scheduled scan identifier
.PARAMETER Filter
Falcon Query Language expression to find scheduled scans for removal
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconScheduledScan
#>
  [CmdletBinding(DefaultParameterSetName='/ods/entities/scheduled-scans/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ods/entities/scheduled-scans/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='Filter',Mandatory)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/ods/entities/scheduled-scans/v1:delete' }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Start-FalconScan {
<#
.SYNOPSIS
Start an on-demand scan
.DESCRIPTION
Requires 'On-demand scans (ODS): Write'.
.PARAMETER FilePath
File path(s) to scan
.PARAMETER SensorDetection
On-sensor machine-learning detection level
.PARAMETER SensorPrevention
On-sensor machine-learning prevention level
.PARAMETER CloudDetection
Cloud-based machine-learning detection level
.PARAMETER CloudPrevention
Cloud-based machine-learning prevention level
.PARAMETER CloudPupDetection
Cloud-based machine-learning PUP detection level
.PARAMETER CloudPupPrevention
Cloud-based machine-learning PUP prevention level
.PARAMETER CpuPriority
Maximum CPU utilization
.PARAMETER ScanExclusion
File path(s) to exclude, in glob syntax
.PARAMETER ScanInclusion
File path(s) to include, in glob syntax
.PARAMETER Quarantine
Quarantine malicious files
.PARAMETER MaxFileSize
Maximum file size, in MB
.PARAMETER EndpointNotification
Show notification to end user
.PARAMETER MaxDuration
Allowable scan duration, in hours
.PARAMETER PauseDuration
Allowable pause duration, in hours
.PARAMETER Description
On-demand scan description
.PARAMETER GroupId
Host Group identifier
.PARAMETER Id
Host identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Start-FalconScan
#>
  [CmdletBinding(DefaultParameterSetName='/ods/entities/scans/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=1)]
    [Alias('file_paths')]
    [string[]]$FilePath,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=2)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('sensor_ml_level_detection')]
    [string]$SensorDetection,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=3)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('sensor_ml_level_prevention')]
    [string]$SensorPrevention,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=4)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_ml_level_detection')]
    [string]$CloudDetection,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=5)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_ml_level_prevention')]
    [string]$CloudPrevention,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=6)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_pup_adware_level_detection')]
    [string]$CloudPupDetection,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=7)]
    [ValidateSet('disabled','cautious','moderate','aggressive','extra_aggressive',IgnoreCase=$false)]
    [Alias('cloud_pup_adware_level_prevention')]
    [string]$CloudPupPrevention,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Mandatory,Position=8)]
    [ValidateSet('up_to_1','up_to_25','up_to_50','up_to_75','up_to_100',IgnoreCase=$false)]
    [Alias('cpu_priority')]
    [string]$CpuPriority,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=9)]
    [Alias('scan_exclusions')]
    [string[]]$ScanExclusion,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=10)]
    [Alias('scan_inclusions')]
    [string[]]$ScanInclusion,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=11)]
    [boolean]$Quarantine,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=12)]
    [Alias('max_file_size')]
    [int32]$MaxFileSize,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=13)]
    [Alias('endpoint_notification')]
    [boolean]$Notification,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=14)]
    [ValidateRange(0,24)]
    [Alias('max_duration')]
    [int]$MaxDuration,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=15)]
    [ValidateRange(0,24)]
    [Alias('pause_duration')]
    [int]$PauseDuration,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',Position=16)]
    [string]$Description,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post')]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('host_groups')]
    [string[]]$GroupId,
    [Parameter(ParameterSetName='/ods/entities/scans/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('hosts','device_id','host_ids','aid')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif (!$PSBoundParameters.GroupId) {
      throw "At least one host group or host identifier value is required."
    } else {
      Invoke-Falcon @Param -UserInput (Set-ScanInteger $PSBoundParameters)
    }
  }
  end {
    if ($List -or $PSBoundParameters.GroupId) {
      if ($List) { $PSBoundParameters['Id'] = @($List) }
      Invoke-Falcon @Param -UserInput (Set-ScanInteger $PSBoundParameters)
    }
  }
}
function Stop-FalconScan {
<#
.SYNOPSIS
Stop an on-demand scan
.DESCRIPTION
Requires 'On-demand scans (ODS): Write'.
.PARAMETER Id
On-demand scan identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Stop-FalconScan
#>
  [CmdletBinding(DefaultParameterSetName='/ods/entities/scan-control-actions/cancel/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/ods/entities/scan-control-actions/cancel/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
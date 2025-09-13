function Get-FalconScheduledReport {
<#
.SYNOPSIS
Search for scheduled report or searches and their execution information
.DESCRIPTION
Requires 'Scheduled Reports: Read'.
.PARAMETER Id
Scheduled report or scheduled search identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Execution
Retrieve information about scheduled report execution(s)
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconScheduledReport
#>
  [CmdletBinding(DefaultParameterSetName='/reports/queries/scheduled-reports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/reports/entities/scheduled-reports/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/reports/entities/report-executions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get',Position=1)]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get',Position=2)]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get',Position=3)]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get',Position=3)]
    [ValidateSet('created_on.asc','created_on.desc','last_updated_on.asc','last_updated_on.desc',
      'last_execution_on.asc','last_execution_on.desc','next_execution_on.asc','next_execution_on.desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get',Position=4)]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get')]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get',Mandatory)]
    [Parameter(ParameterSetName='/reports/entities/report-executions/v1:get',Mandatory)]
    [switch]$Execution,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get')]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get')]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/reports/queries/scheduled-reports/v1:get')]
    [Parameter(ParameterSetName='/reports/queries/report-executions/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif ($Execution -and $Detailed) {
      [void]$PSBoundParameters.Remove('Detailed')
      $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
      if ($Request) { & $MyInvocation.MyCommand.Name -Id $Request -Execution }
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
function Invoke-FalconScheduledReport {
<#
.SYNOPSIS
Execute a scheduled report
.DESCRIPTION
Requires 'Scheduled Reports: Read'.
.PARAMETER Id
Report identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconScheduledReport
#>
  [CmdletBinding(DefaultParameterSetName='/reports/entities/scheduled-reports/execution/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/reports/entities/scheduled-reports/execution/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('raw_array') }}
    }
  }
  process {
    $PSBoundParameters['raw_array'] = @{ id = $PSBoundParameters.Id }
    [void]$PSBoundParameters.Remove('Id')
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Receive-FalconScheduledReport {
<#
.SYNOPSIS
Download a scheduled report or search result
.DESCRIPTION
Requires 'Scheduled Reports: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Report identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconScheduledReport
#>
  [CmdletBinding(DefaultParameterSetName='/reports/entities/report-executions-download/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/reports/entities/report-executions-download/v1:get',
      ValueFromPipelineByPropertyName,Position=1)]
    [Alias('result_metadata','last_execution')]
    [object]$Path,
    [Parameter(ParameterSetName='/reports/entities/report-executions-download/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string]$Id,
    [Parameter(ParameterSetName='/reports/entities/report-executions-download/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
    if ($PSBoundParameters.Id -and !$PSBoundParameters.Path) {
      # If 'Id' is present without 'Path', attempt to retry with report/execution detail
      $Request = Get-FalconScheduledReport -Id $PSBoundParameters.Id -EA 0
      if (!$Request) { $Request = Get-FalconScheduledReport -Execution -Id $PSBoundParameters.Id -EA 0 }
      $Request | & $MyInvocation.MyCommand.Name
    } else {
      $PSBoundParameters.Path = switch ($PSBoundParameters.Path) {
        # Update 'Path' using report detail
        { $_.result_metadata.report_file_name } {
          # Update 'Id' using 'last_execution.id' and use 'result_metadata.report_file_name'
          $PSBoundParameters.Id = $_.id
          $_.result_metadata.report_file_name
        }
        { $_.report_file_name } { $_.report_file_name }
        { $_.report_params.format } {
          # Update 'Id' using 'last_execution.id' and use 'last_execution.id' and 'report_params.format'
          $PSBoundParameters.Id = $_.id
          $_.id,$_.report_params.format -join '.'
        }
        { $_ -is [string] } { $_ }
      }
      $OutPath = Test-OutFile $PSBoundParameters.Path
      if ($OutPath.Category -eq 'ObjectNotFound') {
        Write-Error @OutPath
      } elseif ($OutPath.Category -eq 'WriteError' -and !$PSBoundParameters.Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Redo-FalconScheduledReport {
<#
.SYNOPSIS
Retry a scheduled report execution
.DESCRIPTION
Requires 'Scheduled Reports: Read'.
.PARAMETER Id
Report identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Redo-FalconScheduledReport
#>
  [CmdletBinding(DefaultParameterSetName='/reports/entities/report-executions-retry/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/reports/entities/report-executions-retry/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('raw_array') }}
    }
  }
  process {
    $PSBoundParameters['raw_array'] = @{ id = $PSBoundParameters.id }
    [void]$PSBoundParameters.Remove('Id')
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconReport {
<#
.SYNOPSIS
Search for Falcon Intelligence Sandbox reports
.DESCRIPTION
Requires 'Sandbox (Falcon Intelligence): Read'.
.PARAMETER Id
Report identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Summary
Return a summary version
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconReport
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/queries/reports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/reports/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/falconx/entities/report-summaries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/falconx/entities/report-summaries/v1:get',Mandatory)]
    [switch]$Summary,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/falconx/queries/reports/v1:get')]
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
function Get-FalconSubmission {
<#
.SYNOPSIS
Search for Falcon Intelligence Sandbox submissions
.DESCRIPTION
Requires 'Sandbox (Falcon Intelligence): Read'.
.PARAMETER Id
Submission identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSubmission
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/queries/submissions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/falconx/queries/submissions/v1:get')]
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
function Get-FalconSubmissionQuota {
<#
.SYNOPSIS
Retrieve monthly Falcon Intelligence Sandbox submission quota
.DESCRIPTION
Requires 'Sandbox (Falcon Intelligence): Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSubmissionQuota
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/queries/submissions/v1:get',SupportsShouldProcess)]
  param()
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      RawOutput = $true
    }
  }
  process {
    $Request = Invoke-Falcon @Param -EA 0
    if ($Request.Result.Content) {
      (ConvertFrom-Json ($Request.Result.Content).ReadAsStringAsync().Result).meta.quota
    } elseif ($Request) {
      throw "Unable to retrieve submission quota. Check client permissions."
    }
  }
}
function New-FalconSubmission {
<#
.SYNOPSIS
Submit a sample to the Falcon Intelligence Sandbox
.DESCRIPTION
'Sha256' values are retrieved from files that are uploaded using 'Send-FalconSample'. Files must be uploaded
before they can be provided to the Falcon Intelligence Sandbox.

Requires 'Sandbox (Falcon Intelligence): Write'.
.PARAMETER EnvironmentId
Analysis environment
.PARAMETER Url
A webpage or file URL
.PARAMETER ActionScript
Runtime script for sandbox analysis
.PARAMETER CommandLine
Command line script passed to the submitted file at runtime
.PARAMETER SystemDate
A custom date to use in the analysis environment
.PARAMETER SystemTime
A custom time to use in the analysis environment
.PARAMETER DocumentPassword
Auto-filled for Adobe or Office files that prompt for a password
.PARAMETER NetworkSetting
Network settings to use in the analysis environment
.PARAMETER EnableTor
Route traffic via TOR
.PARAMETER UserTag
Tags to categorize the submission
.PARAMETER SubmitName
Submission name
.PARAMETER Sha256
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconSubmission
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/entities/submissions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Mandatory,Position=1)]
    [ValidateSet('android','macOS_10.15','ubuntu16_x64','win7_x64','win7_x86','win10_x64',IgnoreCase=$false)]
    [Alias('environment_id')]
    [string]$EnvironmentId,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=2)]
    [string]$Url,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=3)]
    [ValidateSet('default','default_maxantievasion','default_randomfiles','default_randomtheme',
      'default_openie',IgnoreCase=$false)]
    [Alias('action_script')]
    [string]$ActionScript,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=4)]
    [Alias('command_line')]
    [string]$CommandLine,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=5)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [Alias('system_date')]
    [string]$SystemDate,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=6)]
    [ValidatePattern('^\d{2}:\d{2}$')]
    [Alias('system_time')]
    [string]$SystemTime,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=7)]
    [Alias('document_password')]
    [string]$DocumentPassword,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=8)]
    [ValidateSet('default','tor','simulated','offline',IgnoreCase=$false)]
    [Alias('network_settings','NetworkSettings')]
    [string]$NetworkSetting,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=9)]
    [Alias('enable_tor')]
    [boolean]$EnableTor,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',Position=10)]
    [Alias('user_tags','UserTags')]
    [string[]]$UserTag,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',ValueFromPipelineByPropertyName,
      Position=11)]
    [Alias('submit_name','file_name')]
    [string]$SubmitName,
    [Parameter(ParameterSetName='/falconx/entities/submissions/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=12)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Sha256
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('user_tags')
          sandbox = @('submit_name','system_date','action_script','environment_id','command_line','system_time',
            'url','document_password','enable_tor','sha256','network_settings')
        }
      }
    }
  }
  process {
    if ($PSBoundParameters.Url -and $PSBoundParameters.Sha256) {
      throw "'Url' and 'Sha256' can not be combined in a submission."
    } else {
      $PSBoundParameters.EnvironmentId = switch ($PSBoundParameters.EnvironmentId) {
        'android' { 200 }
        'macOS_10.15' { 400 }
        'ubuntu16_x64' { 300 }
        'win7_x64' { 110 }
        'win7_x86' { 100 }
        'win10_x64' { 160 }
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Receive-FalconArtifact {
<#
.SYNOPSIS
Download an artifact from a Falcon Intelligence Sandbox report
.DESCRIPTION
Artifact identifier values can be retrieved for specific Falcon Intelligence Sandbox reports using
'Get-FalconReport'.

Requires 'Sandbox (Falcon Intelligence): Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Artifact identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconArtifact
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/entities/artifacts/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get',Mandatory,Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/falconx/entities/artifacts/v1:get')]
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
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Receive-FalconMemoryDump {
<#
.SYNOPSIS
Download a memory dump or extracted strings from a Falcon Intelligence Sandbox report
.DESCRIPTION
Requires 'Sandbox (Falcon Intelligence): Read'.
.PARAMETER Path
Destination path
.PARAMETER BinaryId
Binary content dump identifier
.PARAMETER ExtractId
Extracted string identifier
.PARAMETER HexId
Hex dump identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconMemoryDump
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/entities/memory-dump/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/v1:get',Position=1)]
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/extracted-strings/v1:get',Position=1)]
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/hex-dump/v1:get',Position=1)]
    [ValidatePattern('\.gzip$')]
    [string]$Path,
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('binary_content_id')]
    [string]$BinaryId,
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/extracted-strings/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('extracted_strings_id')]
    [string]$ExtractId,
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/hex-dump/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('hex_dump_id')]
    [string]$HexId,
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/v1:get')]
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/extracted-strings/v1:get')]
    [Parameter(ParameterSetName='/falconx/entities/memory-dump/hex-dump/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream'; 'Accept-Encoding' = 'gzip' }
      Format = @{ Query = @('name','id') }
    }
    $PSBoundParameters['id'] = switch ($PSBoundParameters) {
      { $_.BinaryId } { $PSBoundParameters.BinaryId }
      { $_.ExtractId } { $PSBoundParameters.ExtractId }
      { $_.HexId } { $PSBoundParameters.HexId }
    }
    @('BinaryId','ExtractId','HexId').foreach{ if ($PSBoundParameters.$_) { [void]$PSBoundParameters.Remove($_) }}
  }
  process {
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconReport {
<#
.SYNOPSIS
Remove a Falcon Intelligence Sandbox report
.DESCRIPTION
Requires 'Sandbox (Falcon Intelligence): Write'.
.PARAMETER Id
Report identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconReport
#>
  [CmdletBinding(DefaultParameterSetName='/falconx/entities/reports/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/falconx/entities/reports/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
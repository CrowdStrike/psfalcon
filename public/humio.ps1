function Receive-FalconLookupFile {
<#
.SYNOPSIS
Download a lookup file from Falcon NGSIEM
.DESCRIPTION
Requires 'NGSIEM: Read'.
.PARAMETER Repository
Repository name
.PARAMETER Filename
Lookup file name
.PARAMETER Path
Destination path
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/humio/api/v1/repositories/{repository}/files/{filename}:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files/{filename}:get',Mandatory,
      Position=1)]
    [ValidateSet('3pi_parsers','event_search_all','falcon_for_it_view','forensics_view','investigate_view',
      'search-all',IgnoreCase=$false)]
    [string]$Repository,
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files/{filename}:get',Mandatory,
      Position=2)]
    [string]$Filename,
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files/{filename}:get',Position=3)]
    [string]$Path,
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files/{filename}:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Outfile = 'path' }
      Headers = @{ Accept = 'application/octet-stream' }
    }
  }
  process {
    if (!$PSBoundParameters.Path) { $PSBoundParameters['Path'] = $PSBoundParameters.Filename }
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path csv
    $OutPath = Test-OutFile $PSBoundParameters.Path
    if ($OutPath.Category -eq 'ObjectNotFound') {
      Write-Error @OutPath
    } elseif ($PSBoundParameters.Path) {
      if ($OutPath.Category -eq 'WriteError' -and !$Force) {
        Write-Error @OutPath
      } else {
        @('filename','repository').foreach{
          $Param.Endpoint = $Param.Endpoint -replace "\{$_\}",$PSBoundParameters.$_
          [void]$PSBoundParameters.Remove($_)
        }
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Send-FalconLookupFile {
<#
.SYNOPSIS
Upload a lookup file to Falcon NGSIEM
.DESCRIPTION
Requires 'NGSIEM: Write'.
.PARAMETER Path
Path to lookup file
.PARAMETER Repository
Repository name [default: search-all]
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconLookupFile
#>
  [CmdletBinding(DefaultParameterSetName='/humio/api/v1/repositories/{repository}/files:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('\.csv$')]
    [Alias('file','FullName')]
    [string]$Path,
    [Parameter(ParameterSetName='/humio/api/v1/repositories/{repository}/files:post',Position=2)]
    [ValidateSet('3pi_parsers','event_search_all','falcon_for_it_view','forensics_view','investigate_view',
      'search-all',IgnoreCase=$false)]
    [string]$Repository
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ formdata = @('file') }
      Headers = @{ Accept = 'text/plain'; ContentType = 'multipart/form-data' }
    }
  }
  process {
    if (!$PSBoundParameters.Repository) { $PSBoundParameters['Repository'] = 'search-all' }
    $Param.Endpoint = $Param.Endpoint -replace '\{repository\}',$PSBoundParameters.Repository
    [void]$PSBoundParameters.Remove('Repository')
    Invoke-Falcon @Param -UserInput $PSBoundParameters -RawOutput
  }
}
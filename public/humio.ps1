function Receive-FalconNgsLookupFile {
<#
.SYNOPSIS
Download a Falcon NGSIEM lookup file
.DESCRIPTION
Requires 'NGSIEM: Read'.
.PARAMETER Repository
Repository name
.PARAMETER Filename
Lookup file name
.PARAMETER Path
Destination path [default: .\<filename>.csv]
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsLookupFile
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
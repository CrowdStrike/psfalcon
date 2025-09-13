function Expand-FalconSampleArchive {
<#
.SYNOPSIS
Extract files from an uploaded sample archive to make them available for analysis.

Use the returned 'id' with 'Get-FalconSampleExtraction' to retrieve extraction status.
.DESCRIPTION
Requires 'Sample uploads: Write'.
.PARAMETER ExtractAll
Extract all files from sample [default: True]
.PARAMETER File
Object(s) containing 'name', 'comment', and 'is_confidential' for uniquely handling individual files
.PARAMETER Id
Sample archive identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Expand-FalconSampleArchive
#>
  [CmdletBinding(DefaultParameterSetName='/archives/entities/extractions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/archives/entities/extractions/v1:post',Position=1)]
    [Alias('extract_all')]
    [boolean]$ExtractAll,
    [Parameter(ParameterSetName='/archives/entities/extractions/v1:post',Position=2)]
    [Alias('files')]
    [object[]]$File,
    [Parameter(ParameterSetName='/archives/entities/extractions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('sha256')]
    [string]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($File) {
      # Filter to defined 'files' properties
      @($File).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.files)) }
    }
  }
  end {
    if (!$PSBoundParameters.File -and !$PSBoundParameters.ExtractAll) { $PSBoundParameters['ExtractAll'] = $true }
    if ($List) {
      # Add 'files' as an array and remove remaining value
      $PSBoundParameters['files'] = @($List)
      [void]$PSBoundParameters.Remove('File')
    }
    # Modify 'Format' to ensure 'files' is properly appended and make request
    [void]$Param.Format.Body.Remove('files')
    $Param.Format.Body.root += 'files'
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconSampleArchive {
<#
.SYNOPSIS
Retrieve status for uploaded sample archives or a list of the files inside them
.DESCRIPTION
Requires 'Sample uploads: Read'.
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IncludeFiles
Include list of file names
.PARAMETER Id
Sample archive identifier
.PARAMETER FileList
Return a list of files inside the sample archive
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSampleArchive
#>
  [CmdletBinding(DefaultParameterSetName='/archives/entities/archives/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/archives/entities/archives/v1:get',Position=1)]
    [Alias('include_files')]
    [boolean]$IncludeFiles,
    [Parameter(ParameterSetName='/archives/entities/archive-files/v1:get',Position=2)]
    [int]$Limit,
    [Parameter(ParameterSetName='/archives/entities/archive-files/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/archives/entities/archives/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Parameter(ParameterSetName='/archives/entities/archive-files/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[A-Fa-f0-9-]{32,64}$')]
    [Alias('sha256')]
    [string]$Id,
    [Parameter(ParameterSetName='/archives/entities/archive-files/v1:get',Mandatory)]
    [switch]$FileList
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconSampleExtraction {
<#
.SYNOPSIS
Retrieve status for sample archive extractions or the files inside them
.DESCRIPTION
Requires 'Sample uploads: Read'.
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER IncludeFiles
Include list of file names
.PARAMETER Id
Sample archive identifier
.PARAMETER FileList
Return the list of files extracted from the sample archive
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconSampleExtraction
#>
  [CmdletBinding(DefaultParameterSetName='/archives/entities/extractions/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/archives/entities/extractions/v1:get',Position=1)]
    [Alias('include_files')]
    [boolean]$IncludeFiles,
    [Parameter(ParameterSetName='/archives/entities/extraction-files/v1:get',Position=2)]
    [int]$Limit,
    [Parameter(ParameterSetName='/archives/entities/extraction-files/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/archives/entities/extractions/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Parameter(ParameterSetName='/archives/entities/extraction-files/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[A-Fa-f0-9-]{32,64}$')]
    [Alias('sha256')]
    [string]$Id,
    [Parameter(ParameterSetName='/archives/entities/extraction-files/v1:get',Mandatory)]
    [switch]$FileList
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconSampleArchive {
<#
.SYNOPSIS
Delete a sample archive
.DESCRIPTION
Requires 'Sample uploads: Write'.
.PARAMETER Id
Sample archive identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconSampleArchive
#>
  [CmdletBinding(DefaultParameterSetName='/archives/entities/archives/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/archives/entities/archives/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('sha256')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconSampleArchive {
<#
.SYNOPSIS
Upload an archive containing sample files.

Once upload has been completed, use the returned 'sha256' value with 'Expand-FalconSampleArchive' to extract files
for submission to Falcon Intelligence Sandbox or QuickScan.
.DESCRIPTION
Requires 'Sample uploads: Write'.
.PARAMETER IsConfidential
Prohibit sample(s) from being displayed in MalQuery [default: True]
.PARAMETER Comment
Audit log comment
.PARAMETER Password
Password to extract files from archive
.PARAMETER Name
File name
.PARAMETER Path
Path to local file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconSampleArchive
#>
  [CmdletBinding(DefaultParameterSetName='/archives/entities/archives/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/archives/entities/archives/v2:post',Position=1)]
    [Alias('is_confidential')]
    [boolean]$IsConfidential,
    [Parameter(ParameterSetName='/archives/entities/archives/v2:post',Position=2)]
    [string]$Comment,
    [Parameter(ParameterSetName='/archives/entities/archives/v2:post',Position=3)]
    [string]$Password,
    [Parameter(ParameterSetName='/archives/entities/archives/v2:post',Position=4)]
    [string]$Name,
    [Parameter(ParameterSetName='/archives/entities/archives/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=5)]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        if ($_ -match '\.(7z|zip)$') { $true } else { throw 'Only ZIP and 7z files are accepted.' }
      } else {
        throw "Cannot find path '$_' because it does not exist or is a directory."
      }
    })]
    [Alias('file','FullName')]
    [string]$Path
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if (!$PSBoundParameters.Name) {
      $PSBoundParameters['Name'] = [System.IO.Path]::GetFileName($PSBoundParameters.Path)
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
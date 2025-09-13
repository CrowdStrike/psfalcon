function Get-FalconQuickScan {
<#
.SYNOPSIS
Search for Falcon QuickScan Pro results
.DESCRIPTION
Requires 'QuickScan Pro: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 50]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconQuickScan
#>
  [CmdletBinding(DefaultParameterSetName='/quickscanpro/queries/scans/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quickscanpro/entities/scans/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[A-Fa-f0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get',Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get',Position=2)]
    [ValidateSet('created_timestamp.asc','created_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/quickscanpro/queries/scans/v1:get')]
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
function New-FalconQuickScan {
<#
.SYNOPSIS
Scan a file with Falcon QuickScan Pro
.DESCRIPTION
Requires 'QuickScan Pro: Write'.
.PARAMETER Id
Sha256 hash value
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconQuickScan
#>
  [CmdletBinding(DefaultParameterSetName='/quickscanpro/entities/scans/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quickscanpro/entities/scans/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('sha256')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconQuickScan {
<#
.SYNOPSIS
Remove Falcon QuickScan Pro results
.DESCRIPTION
Requires 'QuickScan Pro: Write'.
.PARAMETER Id
Scan identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconQuickScan
#>
  [CmdletBinding(DefaultParameterSetName='/quickscanpro/entities/scans/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quickscanpro/entities/scans/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{32}$')]
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
function Remove-FalconQuickScanFile {
<#
.SYNOPSIS
Remove a file previously uploaded to Falcon QuickScan Pro
.DESCRIPTION
Requires 'QuickScan Pro: Write'.
.PARAMETER Id
Sample identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconQuickScanFile
#>
  [CmdletBinding(DefaultParameterSetName='/quickscanpro/entities/files/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quickscanpro/entities/files/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [Alias('ids')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Send-FalconQuickScanFile {
<#
.SYNOPSIS
Upload a file for submission to Falcon QuickScan Pro
.DESCRIPTION
Requires 'QuickScan Pro: Write'. Maximum file size is 256MB.
.PARAMETER Scan
Initiate a QuickScan Pro scan once upload is complete
.PARAMETER Path
Path to local file
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconQuickScanFile
#>
  [CmdletBinding(DefaultParameterSetName='/quickscanpro/entities/files/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/quickscanpro/entities/files/v1:post',Position=1)]
    [boolean]$Scan,
    [Parameter(ParameterSetName='/quickscanpro/entities/files/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $true
      } else {
        throw "Cannot find path '$_' because it does not exist or is a directory."
      }
    })]
    [Alias('file','FullName')]
    [string]$Path
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
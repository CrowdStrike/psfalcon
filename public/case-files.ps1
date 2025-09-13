function Edit-FalconNgsCaseFile {
<#
.SYNOPSIS
Modify the description of a file in a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER Description
Case file description
.PARAMETER Id
Case file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsCaseFile
#>
  [CmdletBinding(DefaultParameterSetName='/case-files/entities/file-details/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/case-files/entities/file-details/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Description,
    [Parameter(ParameterSetName='/case-files/entities/file-details/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconNgsCaseFile {
<#
.SYNOPSIS
Search for files in Falcon NGSIEM cases
.DESCRIPTION
Requires 'Cases: Read'.
.PARAMETER Id
Case file identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseFile
#>
  [CmdletBinding(DefaultParameterSetName='/case-files/queries/file-details/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/case-files/entities/file-details/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/case-files/queries/file-details/v1:get',Position=1)]
    [Parameter(ParameterSetName='/case-files/combined/file-details/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/case-files/queries/file-details/v1:get',Position=2)]
    [Parameter(ParameterSetName='/case-files/combined/file-details/v1:get',Position=2)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/case-files/queries/file-details/v1:get')]
    [Parameter(ParameterSetName='/case-files/combined/file-details/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/case-files/combined/file-details/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/case-files/queries/file-details/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/case-files/queries/file-details/v1:get')]
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
function Receive-FalconNgsCaseFile {
<#
.SYNOPSIS
Download files from Falcon NGSIEM cases
.DESCRIPTION
Requires 'Cases: Read'.

Providing multiple identifiers will be bunded into a ZIP archive.
.PARAMETER Id
Case file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconNgsCaseFile
#>
  [CmdletBinding(DefaultParameterSetName='/case-files/entities/files/download/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/case-files/entities/files/download/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [string]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      if ($List.Count -gt 1) { $Param.Endpoint = '/case-files/entities/files/bulk-download/v1:post' }
      $PSBoundParameters['Id'] = $List
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconNgsCaseFile {
<#
.SYNOPSIS
Remove files from a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER Id
Case file identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsCaseFile
#>
  [CmdletBinding(DefaultParameterSetName='/case-files/entities/files/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/case-files/entities/files/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
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
function Send-FalconNgsCaseFile {
<#
.SYNOPSIS
Upload a file to a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconNgsCaseFile
#>
  [CmdletBinding(DefaultParameterSetName='/case-files/entities/files/upload/v1:post',SupportsShouldProcess)]
  param()
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
}
function Get-FalconCaoQuery {
<#
.SYNOPSIS
Search for Falcon Counter Adversary Operations queries
.DESCRIPTION
Requires 'CAO Hunting: Read'.
.PARAMETER Id
Query identifier
.PARAMETER IncludeTranslated
Return translated content when present
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
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCaoQuery
#>
  [CmdletBinding(DefaultParameterSetName='/hunting/queries/intelligence-queries/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/hunting/entities/intelligence-queries/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{64}_[a-fA-F0-9]{64}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/hunting/entities/intelligence-queries/v1:get',Position=2)]
    [ValidateSet('__all__','SPL',IgnoreCase=$false)]
    [Alias('include_translated_content')]
    [string[]]$IncludeTranslated,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/hunting/queries/intelligence-queries/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','include_translated_content','limit','offset','q','sort') }
    }
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
function Receive-FalconCaoQueryArchive {
<#
.SYNOPSIS
Download an archive containing Falcon Counter Adversary Operations queries
.DESCRIPTION
Requires 'CAO Hunting: Read'.
.PARAMETER Path
Destination path
.PARAMETER Language
Query language
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Type
Archive type [default: zip]
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconCaoQueryArchive
#>
  [CmdletBinding(DefaultParameterSetName='/hunting/entities/archive-exports/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/hunting/entities/archive-exports/v1:get',Mandatory,Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/hunting/entities/archive-exports/v1:get',Mandatory,Position=2)]
    [ValidateSet('__all__','cql','snort','suricata','yara',IgnoreCase=$false)]
    [string]$Language,
    [Parameter(ParameterSetName='/hunting/entities/archive-exports/v1:get',Position=3)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/hunting/entities/archive-exports/v1:get',Position=4)]
    [ValidateSet('gzip','zip',IgnoreCase=$false)]
    [Alias('archive_type')]
    [string]$Type,
    [Parameter(ParameterSetName='/hunting/entities/archive-exports/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ Accept = 'application/octet-stream' }
      Format = @{ Outfile = 'path'; Query = @('archive_type','filter','language') }
    }
    [string]$Ext = ($PSBoundParameters.Path | Split-Path -Leaf).Split('.',2)[-1]
    [string[]]$Valid = (Get-Command $Param.Command).Parameters.Type.Attributes.ValidValues
  }
  process {
    if (!$PSBoundParameters.Type) {
      # Check 'Path' for valid 'Type', default to 'zip'
      $PSBoundParameters['Type'] = if ($Ext -and $Valid -contains $Ext) { $Ext } else { 'zip' }
    }
    $PSBoundParameters.Path = Assert-Extension $PSBoundParameters.Path $PSBoundParameters.Type
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
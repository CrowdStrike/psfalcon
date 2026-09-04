function Get-FalconForensicsCollection {
<#
.SYNOPSIS
Search for Falcon Forensics collections
.DESCRIPTION
Requires 'Falcon Forensics: Read'.
.PARAMETER Id
Collection identifier
.PARAMETER Platform
Operating System platform
.PARAMETER HostId
Falcon host identifier
.PARAMETER FfcId
Falcon Forensics Collector identifier
.PARAMETER State
Falcon Forensics Collection state
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconForensicsCollection
#>
  [CmdletBinding(DefaultParameterSetName='/forensics/queries/collections/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=1)]
    [ValidateSet('windows','linux','mac',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=2)]
    [Alias('aids','aid')]
    [string[]]$HostId,
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Position=4)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=3)]
    [Alias('ffcids')]
    [string[]]$FfcId,
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Position=5)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=4)]
    [Alias('states')]
    [string[]]$State,
    [Parameter(ParameterSetName='/forensics/combined/collections/v1:get',Position=1)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=5)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/forensics/combined/collections/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/entities/collections/v1:get',Position=6)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=3)]
    [ValidateSet('deadline|asc','deadline|desc','id|asc','id|desc','modified_timestamp|asc',
      'modified_timestamp|desc','priority|asc','priority|desc','state|asc','state|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/forensics/combined/collections/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get',Position=4)]
    [string]$Limit,
    [Parameter(ParameterSetName='/forensics/combined/collections/v1:get')]
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/forensics/combined/collections/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/forensics/queries/collections/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('aids','ffcids','filter','ids','limit','offset','platform','sort','states') }
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
function Get-FalconForensicsCollector {
<#
.SYNOPSIS
Search for Falcon Forensics collectors
.DESCRIPTION
Requires 'Falcon Forensics: Read'.
.PARAMETER Id
Collector identifier
.PARAMETER Platform
Operating System platform
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconForensicsCollector
#>
  [CmdletBinding(DefaultParameterSetName='/forensics/queries/collectors/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/forensics/entities/collectors/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/forensics/entities/collectors/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get',Position=1)]
    [ValidateSet('windows','linux','mac',IgnoreCase=$false)]
    [string]$Platform,
    [Parameter(ParameterSetName='/forensics/combined/collectors/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/forensics/combined/collectors/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/entities/collectors/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get',Position=3)]
    [ValidateSet('aid|asc','aid|desc','ffcid|asc','ffcid|desc','modified_timestamp|asc','modified_timestamp|desc',
      'platform|asc','platform|desc','state|asc','state|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/forensics/combined/collectors/v1:get',Position=4)]
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get',Position=4)]
    [string]$Limit,
    [Parameter(ParameterSetName='/forensics/combined/collectors/v1:get')]
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/forensics/combined/collectors/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/forensics/queries/collectors/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','platform','sort') }
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
function Get-FalconForensicsConfiguration {
<#
.SYNOPSIS
Search for Falcon Forensics configurations
.DESCRIPTION
Requires 'Falcon Forensics: Read'.
.PARAMETER Id
Configuration identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconForensicsConfiguration
#>
  [CmdletBinding(DefaultParameterSetName='/forensics/queries/configurations/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/forensics/entities/configurations/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/forensics/combined/configurations/v1:get',Position=1)]
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/forensics/combined/configurations/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get',Position=2)]
    [ValidateSet('id|asc','id|desc','name|asc','name|desc','modified_timestamp|asc','modified_timestamp|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/forensics/combined/configurations/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/forensics/combined/configurations/v1:get')]
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/forensics/combined/configurations/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/forensics/queries/configurations/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
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
function Get-FalconForensicsTemplate {
<#
.SYNOPSIS
Search for Falcon Forensics templates
.DESCRIPTION
Requires 'Falcon Forensics: Read'.
.PARAMETER Id
Template identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconForensicsTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/forensics/queries/templates/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/forensics/entities/templates/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/forensics/combined/templates/v1:get',Position=1)]
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/forensics/combined/templates/v1:get',Position=2)]
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get',Position=2)]
    [ValidateSet('id|asc','id|desc','modified_timestamp|asc','modified_timestamp|desc','name|asc','name|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/forensics/combined/templates/v1:get',Position=3)]
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get',Position=3)]
    [string]$Limit,
    [Parameter(ParameterSetName='/forensics/combined/templates/v1:get')]
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/forensics/combined/templates/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/forensics/queries/templates/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','sort') }
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
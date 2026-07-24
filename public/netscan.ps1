function Get-FalconEmNetwork {
<#
.SYNOPSIS
Search for Falcon Exposure Management networks
.DESCRIPTION
Requires 'Network scanning: Read'.
.PARAMETER Id
Network identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconEmNetwork
#>
  [CmdletBinding(DefaultParameterSetName='/netscan/queries/networks/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/netscan/entities/networks/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/netscan/queries/networks/v1:get')]
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
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconEmScan {
<#
.SYNOPSIS
Search for Falcon Exposure Management scans
.DESCRIPTION
Requires 'Network scanning: Read'.
.PARAMETER Id
Scan identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconEmScan
#>
  [CmdletBinding(DefaultParameterSetName='/netscan/queries/scans/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/netscan/entities/scans/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/netscan/queries/scans/v1:get')]
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
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconEmScanRun {
<#
.SYNOPSIS
Search for Falcon Exposure Management scan runs
.DESCRIPTION
Requires 'Network scanning: Read'.
.PARAMETER Id
Scan run identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconEmScanRun
#>
  [CmdletBinding(DefaultParameterSetName='/netscan/queries/scan-runs/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/netscan/entities/scan-runs/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/netscan/queries/scan-runs/v1:get')]
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
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconEmTemplate {
<#
.SYNOPSIS
Search for Falcon Exposure Management scan templates
.DESCRIPTION
Requires 'Network scanning: Read'.
.PARAMETER Id
Scan template identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 100]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconEmTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/netscan/queries/templates/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/netscan/entities/templates/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/netscan/queries/templates/v1:get')]
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
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconEmZone {
<#
.SYNOPSIS
Search for Falcon Exposure Management zones
.DESCRIPTION
Requires 'Network scanning: Read'.
.PARAMETER Id
Zone identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconEmZone
#>
  [CmdletBinding(DefaultParameterSetName='/netscan/queries/zones/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/netscan/entities/zones/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get',Position=1)]
    [Parameter(ParameterSetName='/netscan/combined/zones/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get',Position=2)]
    [Parameter(ParameterSetName='/netscan/combined/zones/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get',Position=3)]
    [Parameter(ParameterSetName='/netscan/combined/zones/v1:get',Position=3)]
    [ValidateRange(1,100)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get')]
    [Parameter(ParameterSetName='/netscan/combined/zones/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get')]
    [Parameter(ParameterSetName='/netscan/combined/zones/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/netscan/queries/zones/v1:get')]
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
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
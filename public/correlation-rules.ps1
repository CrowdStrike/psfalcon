function Get-FalconCorrelationRule {
<#
.SYNOPSIS
Search for Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Read'.
.PARAMETER Id
Correlation rule identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/queries/rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=1)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=2)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=3)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=3)]
    [ValidateSet('created_on|asc','created_on|desc','last_updated_on|asc','last_updated_on|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Position=4)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v1:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v1:get')]
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
function Remove-FalconCorrelationRule {
<#
.SYNOPSIS
Remove Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Id
Correlation rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
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
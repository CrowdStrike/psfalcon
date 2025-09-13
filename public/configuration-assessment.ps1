function Get-FalconConfigAssessment {
<#
.SYNOPSIS
Search for Falcon Spotlight Configuration Assessments
.DESCRIPTION
Requires 'Configuration Assessment: Read'.
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Facet
Include additional properties
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconConfigAssessment
#>
  [CmdletBinding(DefaultParameterSetName='/configuration-assessment/combined/assessments/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get',Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get',Position=2)]
    [ValidateSet('finding.evaluation_logic','finding.rule','host',IgnoreCase=$false)]
    [string[]]$Facet,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get',Position=3)]
    [ValidateSet('created_timestamp|asc','created_timestamp|desc','updated_timestamp|asc',
      'updated_timestamp|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int]$Limit,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get')]
    [string]$After,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/configuration-assessment/combined/assessments/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconConfigAssessmentLogic {
<#
.SYNOPSIS
Retrieve detailed evaluation logic from a configuration assessment
.DESCRIPTION
Requires 'Configuration Assessment: Read'.
.PARAMETER Id
Evaluation logic identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconConfigAssessmentLogic
#>
  [CmdletBinding(DefaultParameterSetName='/configuration-assessment/entities/evaluation-logic/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/configuration-assessment/entities/evaluation-logic/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^([a-fA-F0-9]{32}_?){4}$')]
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
function Get-FalconConfigAssessmentRule {
<#
.SYNOPSIS
Retrieve configuration assessment rule details
.DESCRIPTION
Requires 'Configuration Assessment: Read'.
.PARAMETER Id
Configuration assessment rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconConfigAssessmentRule
#>
  [CmdletBinding(DefaultParameterSetName='/configuration-assessment/entities/rule-details/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/configuration-assessment/entities/rule-details/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}_[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 400 }
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
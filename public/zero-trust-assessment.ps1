function Get-FalconZta {
<#
.SYNOPSIS
Search for Zero Trust Assessment results
.DESCRIPTION
Requires 'Zero Trust Assessment: Read'.
.PARAMETER Id
Host identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
The maximum records to return
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconZta
#>
  [CmdletBinding(DefaultParameterSetName='/zero-trust-assessment/entities/audit/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/zero-trust-assessment/entities/assessments/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get',Mandatory,Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get',Position=2)]
    [ValidateSet('score|desc','score|asc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int]$Limit,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get')]
    [string]$After,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/zero-trust-assessment/queries/assessments/v1:get')]
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
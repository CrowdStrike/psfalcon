function Add-FalconNgsCaseTag {
<#
.SYNOPSIS
Add tags to a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER Id
Case identifier
.PARAMETER Tag
One or more tag values
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconNgsCaseTag
#>
  [CmdletBinding(DefaultParameterSetName='/cases/entities/case-tags/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cases/entities/case-tags/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [Alias('tags')]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/cases/entities/case-tags/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=2)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-CommandName {
<#
.SYNOPSIS
Search for Falcon NGSIEM cases
.DESCRIPTION
Requires 'Cases: Read'.
.PARAMETER Id
Case identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Query
Perform a generic substring search across available fields
.PARAMETER Sort
Property and direction to sort results

('status', 'cid', 'created_timestamp', 'updated_timestamp', 'assigned_to_name', 'assigned_to_userid', 'assigned_to_uuid', 'tags' | sort | %{ "'$_|asc'","'$_|desc'" }) -join ','
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
https://github.com/crowdstrike/psfalcon/wiki/New-CommandName
#>
  [CmdletBinding(DefaultParameterSetName='/cases/queries/cases/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cases/entities/cases/v2:post',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get',Position=3)]
    [ValidateSet('assigned_to_name|asc','assigned_to_name|desc','assigned_to_userid|asc','assigned_to_userid|desc',
      'assigned_to_uuid|asc','assigned_to_uuid|desc','cid|asc','cid|desc','created_timestamp|asc',
      'created_timestamp|desc','status|asc','status|desc','tags|asc','tags|desc','updated_timestamp|asc',
      'updated_timestamp|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get',Position=4)]
    [ValidateRange(1,10000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cases/queries/cases/v1:get')]
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
function Remove-FalconNgsCaseTag {
<#
.SYNOPSIS
Remove tags from a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER Id
Case identifier
.PARAMETER Tag
One or more tag values
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsCaseTag
#>
  [CmdletBinding(DefaultParameterSetName='/cases/entities/case-tags/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cases/entities/case-tags/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/cases/entities/case-tags/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=2)]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
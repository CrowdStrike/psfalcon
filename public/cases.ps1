function Add-FalconNgsCaseEvidence {
<#
.SYNOPSIS
Add alerts or events to a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER AlertId
Alert identifier
.PARAMETER EventId
Event identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconNgsCaseEvidence
#>
  [CmdletBinding(DefaultParameterSetName='/cases/entities/alert-evidence/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cases/entities/alert-evidence/v1:post',Mandatory,Position=1)]
    [Alias('alerts')]
    [string[]]$AlertId,
    [Parameter(ParameterSetName='/cases/entities/event-evidence/v1:post',Mandatory,Position=1)]
    [Alias('events')]
    [string[]]$EventId,
    [Parameter(ParameterSetName='/cases/entities/alert-evidence/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [Parameter(ParameterSetName='/cases/entities/event-evidence/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('alerts','events','id') }}
    }
  }
  process {
    @('alerts','events').foreach{
      # Convert 'id' values into array of objects containing 'id' values
      if ($PSBoundParameters.($_ -replace 's$','id')) {
        $PSBoundParameters[$_] = [PSCustomObject[]]@($PSBoundParameters.($_ -replace 's$','id')).foreach{
          [PSCustomObject]@{ id = $_ }
        }
        [void]$PSBoundParameters.Remove(($_ -replace 's$','id'))
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
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
function Get-FalconNgsCase {
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCase
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
function New-FalconNgsCase {
<#
.SYNOPSIS
Create a Falcon NGSIEM case
.DESCRIPTION
Requires 'Cases: Write'.
.PARAMETER Name
Case name
.PARAMETER Severity
Case severity
.PARAMETER Description
Case description
.PARAMETER Status
Case status
.PARAMETER Evidence
Object containing evidence properties ('alerts', 'events', 'leads')
.PARAMETER Tag
Case tags
.PARAMETER AssignedUuid
User identifier for case assignment
.PARAMETER Template
Object containing case template properties ('id')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsCase
#>
  [CmdletBinding(DefaultParameterSetName='/cases/entities/cases/v2:put',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Severity,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=4)]
    [ValidateSet('new','in_progress','reopened','closed',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=5)]
    [object]$Evidence,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=6)]
    [Alias('tags')]
    [string[]]$Tag,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=7)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('assigned_to_user_uuid')]
    [string]$AssignedUuid,
    [Parameter(ParameterSetName='/cases/entities/cases/v2:put',ValueFromPipelineByPropertyName,Position=8)]
    [object]$Template
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('assigned_to_user_uuid','description','evidence','name','severity','status','tags','template')
        }
      }
    }
    [string[]]$Allowed = 'critical','high','medium','low','informational'
  }
  process {
    $PSBoundParameters.Severity = if ($PSBoundParameters.Severity -as [int32] -is [int32]) {
      # Force [int32] value
      [int32]$PSBoundParameters.Severity
    } elseif ($Allowed -notcontains $PSBoundParameters.Severity) {
      # Error when provided [string] not in list
      throw ('Invalid "Severity" value! [{0}]' -f ((@($Allowed).foreach{ '"{0}"' -f $_ }) -join ','))
    } else {
      # Convert [string] value to [int32]
      switch ($PSBoundParameters.Severity) {
        'critical' { 80 }
        'high' { 60 }
        'medium' { 40 }
        'low' { 20 }
        'informational' { 10 }
      }
    }
    if ($PSBoundParameters.Evidence) {
      # Select 'id' value under 'alerts', 'events', and 'leads'
      $PSBoundParameters.Evidence = $PSBoundParameters.Evidence | Select-Object @{l='alerts';
        e={$_.alerts | Select-Object id}},@{l='events';e={$_.events | Select-Object id}},@{l='leads';
        e={$_.leads | Select-Object id}}
      @('alerts','events','leads').foreach{
        # Ensure 'alerts', 'events', and 'leads' contain arrays of 'id' values
        if ($PSBoundParameters.Evidence.$_.id) {
          $PSBoundParameters.Evidence.$_ = [PSCustomObject[]]@($PSBoundParameters.Evidence.$_)
        } else {
          $PSBoundParameters.Evidence.PSObject.Properties.Remove($_)
        }
      }
    }
    if ($PSBoundParameters.Template) {
      # Select 'id' under 'template'
      $PSBoundParameters.Template = $PSBoundParameters.Template | Select-Object id
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
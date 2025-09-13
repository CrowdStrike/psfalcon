function Add-FalconCompleteActivity {
<#
.SYNOPSIS
Add an activity to a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Type
Activity type
.PARAMETER Content
Activity content
.PARAMETER UserId
User identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconCompleteActivity
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-activity/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
       Position=1)]
    [ValidateSet('comment',IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
       Position=2)]
    [Alias('body')]
    [string]$Content,
    [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/message-center/entities/case-activity/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [Alias('case_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconCompleteCase {
<#
.SYNOPSIS
Modify an existing Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Content
Case content
.PARAMETER DetectionId
Detection identifier
.PARAMETER IncidentId
Incident identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCompleteCase
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/entities/case/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',Position=1)]
    [Alias('body')]
    [string]$Content,
    [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidatePattern('^ldt:[a-fA-F0-9]{32}:\d+$')]
    [Alias('detections','detection_id','DetectionIds')]
    [string[]]$DetectionId,
    [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^inc:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$')]
    [Alias('incidents','incident_id','IncidentIds')]
    [string[]]$IncidentId,
    [Parameter(ParameterSetName='/message-center/entities/case/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('id','body','detections','incidents') }}
    }
    [System.Collections.Generic.List[hashtable]]$LdtList = @()
    [System.Collections.Generic.List[hashtable]]$IncList = @()
  }
  process {
    if ($DetectionId -or $IncidentId) {
      if ($DetectionId) { @($DetectionId).foreach{ $LdtList.Add(@{ id = $_ }) }}
      if ($IncidentId) { @($IncidentId).foreach{ $IncList.Add(@{ id = $_ }) }}
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($LdtList -or $IncList) {
      if ($LdtList) { $PSBoundParameters['DetectionId'] = $LdtList }
      if ($IncList) { $PSBoundParameters['IncidentId'] = $IncList }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconCompleteActivity {
<#
.SYNOPSIS
Search for Falcon Complete case activities
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Id
Activity identifier
.PARAMETER CaseId
Case identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCompleteActivity
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/queries/case-activities/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case-activities/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Mandatory,Position=1)]
    [Alias('case_id')]
    [string]$CaseId,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=3)]
    [ValidateSet('activity.created_time.asc','activity.created_time.desc','activity.type.asc',
      'activity.type.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get',Position=4)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/message-center/queries/case-activities/v1:get')]
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
function Get-FalconCompleteCase {
<#
.SYNOPSIS
Search for Falcon Complete cases
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Id
Case identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCompleteCase
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/queries/cases/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/cases/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=2)]
    [ValidateSet('case.created_time.asc','case.created_time.desc','case.id.asc','case.id.desc',
      'case.last_modified_time.asc','case.last_modified_time.desc','case.status.asc','case.status.desc',
      'case.type.asc','case.type.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/message-center/queries/cases/v1:get')]
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
function New-FalconCompleteCase {
<#
.SYNOPSIS
Create a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Type
Case type
.PARAMETER Title
Case title
.PARAMETER Content
Case content
.PARAMETER DetectionId
Detection identifier
.PARAMETER IncidentId
Incident identifier
.PARAMETER MalwareSubmissionId
Malware submission identifier
.PARAMETER ReconRuleType
Recon rule type
.PARAMETER UserId
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCompleteCase
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/entities/case/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',Mandatory,Position=1)]
    [ValidateSet('fc:detection-support','fc:contact','fc:falcon-product-support','fc:incident-support',
      IgnoreCase=$false)]
    [string]$Type,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',Mandatory,Position=2)]
    [string]$Title,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',Mandatory,Position=3)]
    [Alias('body')]
    [string]$Content,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidatePattern('^ldt:[a-fA-F0-9]{32}:\d+$')]
    [ValidateScript({
      if ($PSBoundParameters.Type -eq 'fc:detection-support') {
        $true
      } else {
        throw "Detection identifiers are used with type 'fc:detection-support'."
      }
    })]
    [Alias('detections','detection_id','DetectionIds')]
    [string[]]$DetectionId,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidatePattern('^inc:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$')]
    [ValidateScript({
      if ($PSBoundParameters.Type -eq 'fc:incident-support') {
        $true
      } else {
        throw "Incident identifiers are used with type 'fc:incident-support'."
      }
    })]
    [Alias('incidents','incident_id','IncidentIds')]
    [string[]]$IncidentId,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('malware_submission_id')]
    [string]$MalwareSubmissionId,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',ValueFromPipelineByPropertyName,
      Position=7)]
    [Alias('recon_rule_type')]
    [string]$ReconRuleType,
    [Parameter(ParameterSetName='/message-center/entities/case/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=8)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('body','detections','incidents','malware_submission_id','recon_rule_type',
        'title','type','user_uuid') }}
    }
    [System.Collections.Generic.List[hashtable]]$LdtList = @()
    [System.Collections.Generic.List[hashtable]]$IncList = @()
  }
  process {
    if ($DetectionId -or $IncidentId) {
      if ($DetectionId) { @($DetectionId).foreach{ $LdtList.Add(@{ id = $_ }) }}
      if ($IncidentId) { @($IncidentId).foreach{ $IncList.Add(@{ id = $_ }) }}
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($LdtList -or $IncList) {
      if ($LdtList) { $PSBoundParameters['DetectionId'] = $LdtList }
      if ($IncList) { $PSBoundParameters['IncidentId'] = $IncList }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Receive-FalconCompleteAttachment {
<#
.SYNOPSIS
Download a Falcon Complete case attachment
.DESCRIPTION
Requires 'Message Center: Read'.
.PARAMETER Path
Destination path
.PARAMETER Id
Attachment identifier
.PARAMETER Force
Overwrite an existing file when present
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Receive-FalconCompleteAttachment
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-attachment/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get',Mandatory,Position=1)]
    [string]$Path,
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [string]$Id,
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:get')]
    [switch]$Force
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = Get-EndpointFormat $PSCmdlet.ParameterSetName
    }
    $Param.Format['Outfile'] = 'path'
  }
  process {
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
function Send-FalconCompleteAttachment {
<#
.SYNOPSIS
Upload and attach a file to a Falcon Complete case
.DESCRIPTION
Requires 'Message Center: Write'.
.PARAMETER Path
Path to local file
.PARAMETER UserId
User identifier
.PARAMETER Id
Case identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Send-FalconCompleteAttachment
#>
  [CmdletBinding(DefaultParameterSetName='/message-center/entities/case-attachment/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,Position=1)]
    [ValidatePattern('\.(bmp|csv|doc(x?)|gif|jp(e?)g|pdf|png|ppt(x?)|txt|xls(x?))$')]
    [ValidateScript({
      if (Test-Path $_ -PathType Leaf) {
        $Leaf = Split-Path $_ -Leaf
        if ($Leaf -notmatch '^[a-z0-9-_\.\s]+$') {
          throw 'Filename contains invalid characters.'
        } elseif (($Leaf -Split '.')[0].Length -gt 255) {
          throw 'Maximum filename length is 255 characters.'
        } elseif ((Get-Item $_).Length/15MB -ge 1) {
          throw 'Maximum filesize is 15MB.'
        } else {
          $true
        }
      } else {
        throw "Cannot find path '$_' because it does not exist or is a directory."
      }
    })]
    [Alias('file')]
    [string]$Path,
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/message-center/entities/case-attachment/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [Alias('case_id')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Headers = @{ ContentType = 'multipart/form-data' }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
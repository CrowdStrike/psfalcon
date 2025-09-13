function Edit-FalconCorrelationRule {
<#
.SYNOPSIS
Modify Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Id
Correlation 'rule_id' (specific version)
.PARAMETER Name
Correlation rule name
.PARAMETER Description
Correlation rule description
.PARAMETER MitreAttack
An object containing MITRE ATT&CK 'tactic_id' and 'technique_id'
.PARAMETER Severity
Correlation rule severity
.PARAMETER Search
An object containing 'search' properties ('filter', 'lookback', 'outcome', 'trigger_mode', 'use_ingest_time')
.PARAMETER Operation
An object containing 'operation' properties ('schedule', 'start_on', 'stop_on')
.PARAMETER Status
Correlation rule status
.PARAMETER State
Correlation rule state
.PARAMETER Notification
An object containing 'notifications' properties ('config', 'options', 'type')
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('mitre_attack')]
    [object[]]$MitreAttack,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidateSet(10,30,50,70,90)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=6)]
    [object]$Search,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=7)]
    [object]$Operation,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=8)]
    [ValidateSet('active','inactive',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=9)]
    [ValidateSet('published','unpublished',IgnoreCase=$false)]
    [string]$State,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('notifications')]
    [object[]]$Notification,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:patch',ValueFromPipelineByPropertyName,
      Position=11)]
    [string]$Comment
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('comment','description','id','mitre_attack','name','notifications','operation','search',
            'severity','state','status')
        }
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters -BodyArray }
}
function Get-FalconCorrelationRule {
<#
.SYNOPSIS
Search for Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Read'.
.PARAMETER Id
Correlation rule identifier (specific version)
.PARAMETER RuleId
Correlation 'rule_id' (latest version only)
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
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/queries/rules/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/correlation-rules/entities/latest-rules/v1:get',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('rule_ids')]
    [string[]]$RuleId,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get',Position=1)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get',Position=2)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get',Position=2)]
    [Alias('q')]
    [string]$Query,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get',Position=3)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get',Position=3)]
    [ValidateSet('created_on|asc','created_on|desc','last_updated_on|asc','last_updated_on|desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get',Position=4)]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get',Position=4)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/correlation-rules/combined/rules/v2:get')]
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/correlation-rules/queries/rules/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif ($RuleId) {
      @($RuleId).foreach{ $List.Add($_) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      if ($RuleId) {
        # Add unique 'rule_id' values
        $PSBoundParameters['rule_ids'] = @($List | Select-Object -Unique)
        [void]$PSBoundParameters.Remove('RuleId')
      } else {
        $PSBoundParameters['ids'] = @($List)
        [void]$PSBoundParameters.Remove('Id')
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconCorrelationRule {
<#
.SYNOPSIS
Create Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Name
Correlation rule name
.PARAMETER Description
Correlation rule description
.PARAMETER Cid
Customer identifier
.PARAMETER MitreAttack
An object containing MITRE ATT&CK 'tactic_id' and 'technique_id'
.PARAMETER Severity
Correlation rule severity
.PARAMETER Search
An object containing 'search' properties ('filter', 'lookback', 'outcome', 'trigger_mode', 'use_ingest_time')
.PARAMETER Operation
An object containing 'operation' properties ('schedule', 'start_on', 'stop_on')
.PARAMETER Status
Correlation rule status
.PARAMETER TemplateId
Correlation rule template identifier
.PARAMETER Notification
An object containing 'notifications' properties ('config', 'options', 'type')
.PARAMETER TriggerOnCreate
Trigger correlation rule upon creation
.PARAMETER Comment
Audit log comment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('customer_id')]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('mitre_attack')]
    [object[]]$MitreAttack,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=5)]
    [ValidateSet(10,30,50,70,90)]
    [int32]$Severity,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=6)]
    [object]$Search,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=7)]
    [object]$Operation,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=8)]
    [ValidateSet('active','inactive',IgnoreCase=$false)]
    [string]$Status,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=9)]
    [Alias('template_id')]
    [string]$TemplateId,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',ValueFromPipelineByPropertyName,
      Position=10)]
    [Alias('notifications')]
    [object[]]$Notification,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Position=11)]
    [Alias('trigger_on_create')]
    [boolean]$TriggerOnCreate,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:post',Position=12)]
    [string]$Comment
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{
          root = @('comment','customer_id','description','mitre_attack','name','notifications','operation',
            'search','severity','status','template_id','trigger_on_create')
        }
      }
    }
  }
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconCorrelationRule {
<#
.SYNOPSIS
Remove Falcon NGSIEM correlation rules
.DESCRIPTION
Requires 'Correlation Rules: Write'.
.PARAMETER Id
Correlation rule identifier (specific version)
.PARAMETER RuleId
Correlation 'rule_id' (all versions)
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCorrelationRule
#>
  [CmdletBinding(DefaultParameterSetName='/correlation-rules/entities/rules/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/correlation-rules/entities/rule-versions/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/correlation-rules/entities/rules/v1:delete',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string[]]$RuleId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif ($RuleId) {
      @($RuleId).foreach{ $List.Add($_) }
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['ids'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
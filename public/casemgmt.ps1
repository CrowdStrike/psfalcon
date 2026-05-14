function Edit-FalconNgsCaseNotificationGroup {
<#
.SYNOPSIS
Modify a Falcon NGSIEM case notification group
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
Notification group name
.PARAMETER Description
Notification group description
.PARAMETER Channel
Objects containing 'channels' properties ('config_id', 'config_name', 'params', 'type')
.PARAMETER Id
Notification group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsCaseNotificationGroup
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/notification-groups/v2:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('channels')]
    [object[]]$Channel,
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('channels','description','id','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconNgsCaseSla {
<#
.SYNOPSIS
Modify a Falcon NGSIEM case SLA
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
SLA name
.PARAMETER Description
SLA description
.PARAMETER Goal
Objects containing 'goals' properties ('duration_seconds', 'escalation_policy', 'type')
.PARAMETER Id
SLA identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsCaseSla
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/slas/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:patch',ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:patch',ValueFromPipelineByPropertyName,Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:patch',ValueFromPipelineByPropertyName,Position=3)]
    [Alias('goals')]
    [object[]]$Goal,
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('description','goals','id','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconNgsCaseTemplate {
<#
.SYNOPSIS
Modify a Falcon NGSIEM case template
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
Case template name
.PARAMETER Description
Case template description
.PARAMETER SlaId
SLA identifier
.PARAMETER Field
Objects containing 'fields' properties ('data_type', 'input_type', 'multivalued', 'name', 'options', 'required')
.PARAMETER Id
Case template identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconNgsCaseTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/templates/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('sla_id')]
    [string]$SlaId,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:patch',ValueFromPipelineByPropertyName,
      Position=4)]
    [Alias('fields')]
    [object[]]$Field,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('description','fields','id','name','sla_id') }}
    }
  }
  process {
    if ($PSBoundParameters.Field) {
      # Select required properties under 'fields' and 'options'
      [PSCustomObject[]]$PSBoundParameters.Field = @($PSBoundParameters.Field).foreach{
        @([PSCustomObject]$_ | Select-Object data_type,input_type,multivalued,name,options,required).foreach{
          if ($_.options) { [PSCustomObject[]]$_.options = @($_.options | Select-Object id,value) }
          $_
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconNgsCaseAccessTag {
<#
.SYNOPSIS
Search for Falcon NGSIEM case access tags
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
Access tag identifier
.PARAMETER WithHasAccess
Evaluate FGAC and return has_access property
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER After
Pagination token to retrieve the next set of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseAccessTag
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/access-tags/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/access-tags/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/entities/access-tags/v1:get',Position=2)]
    [Alias('with_has_access')]
    [boolean]$WithHasAccess,
    [Parameter(ParameterSetName='/casemgmt/queries/access-tags/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/access-tags/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/casemgmt/queries/access-tags/v1:get',Position=3)]
    [ValidateRange(1,200)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/access-tags/v1:get')]
    [string]$After
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('after','filter','ids','limit','sort','with_has_access') }
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
function Get-FalconNgsCaseField {
<#
.SYNOPSIS
Search for Falcon NGSIEM case fields
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
Field identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseField
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/fields/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/fields/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get',Position=2)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/fields/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset') }
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
function Get-FalconNgsCaseNotificationGroup {
<#
.SYNOPSIS
Search for Falcon NGSIEM case notification groups
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
Notification group identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseNotificationGroup
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/notification-groups/v2:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v2:get')]
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
function Get-FalconNgsCaseSla {
<#
.SYNOPSIS
Search for Falcon NGSIEM case SLAs
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
SLA identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseSla
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/slas/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get')]
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
function Get-FalconNgsCaseTemplate {
<#
.SYNOPSIS
Search for Falcon NGSIEM case templates
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
Case template identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/templates/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/templates/v1:get')]
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
function Get-FalconNgsCaseTemplateSnapshot {
<#
.SYNOPSIS
Search for Falcon NGSIEM case template snapshots
.DESCRIPTION
Requires 'Case Templates: Read'.
.PARAMETER Id
Case template snapshot identifier
.PARAMETER TemplateId
Template identifiers to return the latest snapshot
.PARAMETER Version
Retrieve a specific template version, or provide zero to return the latest snapshot
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconNgsCaseTemplateSnapshot
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/template-snapshots/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/template-snapshots/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/entities/template-snapshots/v1:get',Position=1)]
    [Alias('template_ids')]
    [string[]]$TemplateId,
    [Parameter(ParameterSetName='/casemgmt/entities/template-snapshots/v1:get',Position=2)]
    [Alias('versions')]
    [int32[]]$Version,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get',Position=2)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/template-snapshots/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('filter','ids','limit','offset','template_ids','versions') }
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
function New-FalconNgsCaseNotificationGroup {
<#
.SYNOPSIS
Create a Falcon NGSIEM case notification group
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
Notification group name
.PARAMETER Description
Notification group description
.PARAMETER Channel
Objects containing 'channels' properties ('config_id', 'config_name', 'params', 'type')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsCaseNotificationGroup
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/notification-groups/v2:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('channels')]
    [object[]]$Channel
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('channels','description','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconNgsCaseSla {
<#
.SYNOPSIS
Create a Falcon NGSIEM case SLA
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
SLA name
.PARAMETER Description
SLA description
.PARAMETER Goal
Objects containing 'goals' properties ('duration_seconds', 'escalation_policy', 'type')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsCaseSla
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/slas/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:post',ValueFromPipelineByPropertyName,Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:post',ValueFromPipelineByPropertyName,Position=3)]
    [Alias('goals')]
    [object[]]$Goal
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('description','goals','name') }}
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconNgsCaseTemplate {
<#
.SYNOPSIS
Create a Falcon NGSIEM case template
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Name
Case template name
.PARAMETER Description
Case template description
.PARAMETER SlaId
SLA identifier
.PARAMETER Field
Objects containing 'fields' properties ('data_type', 'input_type', 'multivalued', 'name', 'options', 'required')
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconNgsCaseTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/templates/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:post',ValueFromPipelineByPropertyName,Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:post',ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('sla_id')]
    [string]$SlaId,
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:post',ValueFromPipelineByPropertyName,Position=4)]
    [Alias('fields')]
    [object[]]$Field
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('description','fields','name','sla_id') }}
    }
  }
  process {
    if ($PSBoundParameters.Field) {
      [PSCustomObject[]]$PSBoundParameters.Field = @($PSBoundParameters.Field).foreach{
        # Select required properties under 'fields' and 'options'
        @([PSCustomObject]$_ | Select-Object data_type,input_type,multivalued,name,options,required).foreach{
          if ($_.options) { [PSCustomObject[]]$_.options = @($_.options | Select-Object value) }
          $_
        }
      }
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters 
  }
}
function Remove-FalconNgsCaseNotificationGroup {
<#
.SYNOPSIS
Remove Falcon NGSIEM case notification groups
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Id
Notification group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsCaseNotificationGroup
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/notification-groups/v2:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
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
function Remove-FalconNgsCaseSla {
<#
.SYNOPSIS
Remove Falcon NGSIEM case SLAs
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Id
SLA identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsCaseSla
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/slas/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/slas/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
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
function Remove-FalconNgsCaseTemplate {
<#
.SYNOPSIS
Remove Falcon NGSIEM case templates
.DESCRIPTION
Requires 'Case Templates: Write'.
.PARAMETER Id
Case template identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconNgsCaseTemplate
#>
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/templates/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/templates/v1:delete',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('ids') }
    }
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
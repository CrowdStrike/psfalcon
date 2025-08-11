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
  [CmdletBinding(DefaultParameterSetName='/casemgmt/queries/notification-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get',Position=2)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/casemgmt/queries/notification-groups/v1:get')]
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
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/casemgmt/queries/slas/v1:get',Position=2)]
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
  [CmdletBinding(DefaultParameterSetName='/casemgmt/entities/notification-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/casemgmt/entities/notification-groups/v1:delete',Mandatory,
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
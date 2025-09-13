function Edit-FalconInstallTokenSetting {
<#
.SYNOPSIS
Update installation token settings
.DESCRIPTION
Requires 'Installation token settings: Write'.
.PARAMETER TokensRequired
Installation token requirement
.PARAMETER MaxActiveToken
Maximum number of active installation tokens
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconInstallTokenSetting
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/entities/customer-settings/v1:patch',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/customer-settings/v1:patch',Position=1)]
    [Alias('tokens_required')]
    [boolean]$TokenRequired,
    [Parameter(ParameterSetName='/installation-tokens/entities/customer-settings/v1:patch',Position=2)]
    [Alias('max_active_tokens')]
    [int]$MaxActiveToken
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconInstallToken {
<#
.SYNOPSIS
Modify installation tokens
.DESCRIPTION
Requires 'Installation tokens: Write'.
.PARAMETER Label
Installation token label
.PARAMETER ExpiresTimestamp
Installation token expiration time (RFC3339), or 'null'
.PARAMETER Revoked
Set revocation status
.PARAMETER Id
Installation token identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconInstallToken
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/entities/tokens/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:patch',
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Label,
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:patch',
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|null)$')]
    [Alias('expires_timestamp')]
    [string]$ExpiresTimestamp,
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:patch',
      ValueFromPipelineByPropertyName,Position=3)]
    [boolean]$Revoked,
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=4)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
function Get-FalconInstallToken {
<#
.SYNOPSIS
Search for installation tokens
.DESCRIPTION
Requires 'Installation tokens: Read'.
.PARAMETER Id
Installation token identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconInstallToken
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/queries/tokens/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/installation-tokens/queries/tokens/v1:get')]
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
function Get-FalconInstallTokenEvent {
<#
.SYNOPSIS
Search for installation token audit events
.DESCRIPTION
Requires 'Installation tokens: Read'.
.PARAMETER Id
Installation token audit event identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconInstallTokenEvent
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/queries/audit-events/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/audit-events/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get',Position=3)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/installation-tokens/queries/audit-events/v1:get')]
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
function Get-FalconInstallTokenSetting {
<#
.SYNOPSIS
Retrieve installation token settings
.DESCRIPTION
Returns the maximum number of allowed installation tokens, and whether or not they are required for
installation of the Falcon sensor.

Requires 'Installation tokens: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconInstallTokenSetting
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/entities/customer-settings/v1:get',
    SupportsShouldProcess)]
  param()
  process { Invoke-Falcon -Command $MyInvocation.MyCommand.Name -Endpoint $PSCmdlet.ParameterSetName }
}
function New-FalconInstallToken {
<#
.SYNOPSIS
Create an installation token
.DESCRIPTION
Requires 'Installation tokens: Write'.
.PARAMETER Label
Installation token label
.PARAMETER ExpiresTimestamp
Installation token expiration time (RFC3339), or 'null'
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconInstallToken
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/entities/tokens/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:post',Mandatory,Position=1)]
    [string]$Label,
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:post',Mandatory,Position=2)]
    [ValidatePattern('^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|null)$')]
    [Alias('expires_timestamp')]
    [string]$ExpiresTimestamp
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconInstallToken {
<#
.SYNOPSIS
Remove installation tokens
.DESCRIPTION
Requires 'Installation tokens: Write'.
.PARAMETER Id
Installation token identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconInstallToken
#>
  [CmdletBinding(DefaultParameterSetName='/installation-tokens/entities/tokens/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/installation-tokens/entities/tokens/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
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
function Edit-FalconContentPolicy {
<#
.SYNOPSIS
Modify Content Update policies
.DESCRIPTION
Requires 'Content Update Policies: Write'.
.PARAMETER Id
Policy identifier
.PARAMETER Name
Policy name
.PARAMETER Description
The new description to assign to the policy
.PARAMETER Setting
Policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconContentPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/content-update/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({Confirm-Parameter $_ 'Edit-FalconContentPolicy' '/policy/entities/content-update/v1:patch'})]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:patch',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:patch',Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:patch',Position=3)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:patch',Position=4)]
    [Alias('settings')]
    [object]$Setting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/content-update/v1:patch' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      # Filter to defined 'resources' properties
      @($InputObject).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.resources)) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Modify in groups of 100
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('resources') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['resources'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Get-FalconContentPolicy {
<#
.SYNOPSIS
Search for Content Update policies
.DESCRIPTION
Requires 'Content Update Policies: Read'.
.PARAMETER Id
Policy identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContentPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/content-update/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get',Position=1)]
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get',Position=2)]
    [ValidateSet('created_by.asc','created_by.desc','created_timestamp.asc','created_timestamp.desc','enabled.asc',
      'enabled.desc','modified_by.asc','modified_by.desc','modified_timestamp.asc','modified_timestamp.desc',
      'name.asc','name.desc','platform_name.asc','platform_name.desc','precedence.asc','precedence.desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get',Position=3)]
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/content-update/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/content-update/v1:get')]
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
function Get-FalconContentPolicyMember {
<#
.SYNOPSIS
Search for Content Update policy members
.DESCRIPTION
Requires 'Content Update Policies: Read'.
.PARAMETER Id
Policy identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContentPolicyMember
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/content-update-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get',ValueFromPipelineByPropertyName,
      ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$Id,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get',Position=2)]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get',Position=2)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get',Position=3)]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get',Position=3)]
    [string]$Sort,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get',Position=4)]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get',Position=4)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get',Mandatory)]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/policy/combined/content-update-members/v1:get')]
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/policy/queries/content-update-members/v1:get')]
    [switch]$Total
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconContentVersion {
<#
.SYNOPSIS
List Content Update versions available for policy pinning
.DESCRIPTION
Requires 'Content Update Policies: Read'.
.PARAMETER Category
Content category
.PARAMETER Sort
Property and direction to sort results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconContentVersion
#>
  [CmdletBinding(DefaultParameterSetName='/policy/queries/content-update-pin-versions/v1:get',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/queries/content-update-pin-versions/v1:get',Mandatory,Position=1)]
    [ValidateSet('rapid_response_al_bl_listing','sensor_operations','system_critical','vulnerability_management',
      IgnoreCase=$false)]
    [string]$Category,
    [Parameter(ParameterSetName='/policy/queries/content-update-pin-versions/v1:get',Position=2)]
    [ValidateSet('deployed_timestamp.asc','deployed_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Invoke-FalconContentPolicyAction {
<#
.SYNOPSIS
Perform actions on Content Update policies
.DESCRIPTION
Requires 'Content Update Policies: Write'.
.PARAMETER Name
Action to perform
.PARAMETER GroupId
Host group identifier
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconContentPolicyAction
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/content-update-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/content-update-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('add-host-group','disable','enable','override-allow','override-pause','override-revert',
      'remove-host-group','remove-pinned-content-version','set-pinned-content-version',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/content-update-actions/v1:post',Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [string]$GroupId,
    [Parameter(ParameterSetName='/policy/entities/content-update-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('action_name'); Body = @{ root = @('ids','action_parameters') }}
    }
    $Message = $Param.Command,("$(if ($GroupId) { $Name,$GroupId -join ' ' } else { $Name })") -join ': '
  }
  process {
    if ($PSCmdlet.ShouldProcess($Id,$Message)) {
      $PSBoundParameters['ids'] = @($PSBoundParameters.Id)
      [void]$PSBoundParameters.Remove('Id')
      if ($PSBoundParameters.GroupId) {
        $PSBoundParameters['action_parameters'] = @(@{ name = 'group_id'; value = $PSBoundParameters.GroupId })
        [void]$PSBoundParameters.Remove('GroupId')
      }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconContentPolicy {
<#
.SYNOPSIS
Create Content Update policies
.DESCRIPTION
Requires 'Content Update Policies: Write'.
.PARAMETER InputObject
One or more policies to create in a single request
.PARAMETER Name
Policy name
.PARAMETER Description
Policy description
.PARAMETER Setting
Hashtable of policy settings
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconContentPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/content-update/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='Pipeline',Mandatory,ValueFromPipeline)]
    [ValidateScript({Confirm-Parameter $_ 'New-FalconContentPolicy' '/policy/entities/content-update/v1:post'})]
    [Alias('resources','Array')]
    [object[]]$InputObject,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:post',Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:post',Position=3)]
    [Alias('settings')]
    [object]$Setting
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = '/policy/entities/content-update/v1:post' }
    $Param['Format'] = Get-EndpointFormat $Param.Endpoint
    [System.Collections.Generic.List[PSCustomObject]]$List = @()
  }
  process {
    if ($InputObject) {
      # Filter to defined 'resources' properties
      @($InputObject).foreach{ $List.Add(([PSCustomObject]$_ | Select-Object $Param.Format.Body.resources)) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      # Create in groups of 100
      [void]$PSBoundParameters.Remove('InputObject')
      $Param.Format = @{ Body = @{ root = @('resources') } }
      for ($i = 0; $i -lt $List.Count; $i += 100) {
        $PSBoundParameters['resources'] = @($List[$i..($i + 99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconContentPolicy {
<#
.SYNOPSIS
Remove Content Update policies
.DESCRIPTION
Requires 'Content Update Policies: Write'.
.PARAMETER Id
Policy identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconContentPolicy
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/content-update/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/content-update/v1:delete',Mandatory,
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
function Set-FalconContentPrecedence {
<#
.SYNOPSIS
Set Content Update policy precedence
.DESCRIPTION
All policy identifiers must be supplied in order (with the exception of the 'platform_default' policy) to define
policy precedence.

Requires 'Content Update Policies: Write'.
.PARAMETER Id
Policy identifiers in desired precedence order
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Set-FalconContentPrecedence
#>
  [CmdletBinding(DefaultParameterSetName='/policy/entities/content-update-precedence/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/policy/entities/content-update-precedence/v1:post',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
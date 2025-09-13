function Add-FalconCidGroupMember {
<#
.SYNOPSIS
Add a CID member to a Falcon Flight Control CID group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
CID group identifier
.PARAMETER Cid
Customer identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconCidGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/cid-group-members/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-group-members/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/mssp/entities/cid-group-members/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [Alias('cids','child_cid')]
    [string[]]$Cid
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Cid) {
      @($Cid).foreach{
        $Value = Confirm-CidValue $_
        if ($Value) { $List.Add($Value) }
      }
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Cid'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Add-FalconGroupRole {
<#
.SYNOPSIS
Assign roles between Falcon Flight Control CID and user groups
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER CidGroupId
CID group identifier
.PARAMETER UserGroupId
User Group identifier
.PARAMETER RoleId
Role identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconGroupRole
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/mssp-roles/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$CidGroupId,
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$UserGroupId,
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:post',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('role_ids','RoleIds')]
    [string[]]$RoleId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($RoleId) { @($RoleId).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['RoleId'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Add-FalconUserGroupMember {
<#
.SYNOPSIS
Add a user to a Falcon Flight Control user group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
User group identifier
.PARAMETER UserId
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconUserGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/user-group-members/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-group-members/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/mssp/entities/user-group-members/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuids','UserIds')]
    [string[]]$UserId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($UserId) { @($UserId).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['UserId'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Edit-FalconCidGroup {
<#
.SYNOPSIS
Modify a Falcon Flight Control CID group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Name
CID group name
.PARAMETER Description
CID group description
.PARAMETER Id
CID group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconCidGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/cid-groups/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:patch',Mandatory,ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconUserGroup {
<#
.SYNOPSIS
Modify a Falcon Flight Control user group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
User group identifier
.PARAMETER Name
User group name
.PARAMETER Description
User group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconUserGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/user-groups/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$Id
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconCidGroup {
<#
.SYNOPSIS
Search for Falcon Flight Control CID groups
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
CID group identifier
.PARAMETER Name
CID group name
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCidGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/cid-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v2:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','cid_group_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get',Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get',Position=2)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc','name.asc','name.desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/cid-groups/v1:get')]
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
function Get-FalconCidGroupMember {
<#
.SYNOPSIS
Search for Falcon Flight Control CID group members
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
CID group identifier
.PARAMETER Cid
Customer identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCidGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/cid-group-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-group-members/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','cid_group_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [Alias('child_cid')]
    [string]$Cid,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get',Position=2)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/cid-group-members/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } else {
      if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconGroupRole {
<#
.SYNOPSIS
Search for Falcon Flight Control user group roles
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
Combined group identifier [<cid_group_id>:<user_group_id>]
.PARAMETER CidGroupId
CID group identifier
.PARAMETER UserGroupId
User group identifier
.PARAMETER RoleId
Role group identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconGroupRole
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/mssp-roles/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:get',Mandatory,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get',ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$CidGroupId,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get',ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$UserGroupId,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get',ValueFromPipelineByPropertyName,Position=3)]
    [Alias('role_id')]
    [string]$RoleId,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get',Position=4)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get',Position=5)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/mssp-roles/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{ $List.Add($_) }
    } elseif (!$Id -and !$CidGroupId -and !$UserGroupId) {
      throw "'CidGroupId' or 'UserGroupId' must be provided."
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconMemberCid {
<#
.SYNOPSIS
Search for Falcon Flight Control member CIDs
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
Member CID identifier
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconMemberCid
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/children/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/children/GET/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','child_cid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get',Position=2)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/children/v1:get')]
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
function Get-FalconUserGroup {
<#
.SYNOPSIS
Search for Falcon Flight Control user groups
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
User group identifier
.PARAMETER Name
User group name
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconUserGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/user-groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v2:get',Mandatory,ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','user_group_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get',Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get',Position=2)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc','name.asc','name.desc',
      IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/user-groups/v1:get')]
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
function Get-FalconUserGroupMember {
<#
.SYNOPSIS
Search for members of a Falcon Flight Control user group,or groups assigned to a user
.DESCRIPTION
Requires 'Flight Control: Read'.
.PARAMETER Id
User group identifier, to find group members
.PARAMETER UserId
A user identifier, to find group membership
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconUserGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/queries/user-group-members/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-group-members/v2:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','user_group_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get',Position=2)]
    [ValidateSet('last_modified_timestamp.asc','last_modified_timestamp.desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get',Position=3)]
    [ValidateRange(1,5000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/mssp/queries/user-group-members/v1:get')]
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
function New-FalconCidGroup {
<#
.SYNOPSIS
Create a Falcon Flight Control CID group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Name
CID group name
.PARAMETER Description
CID group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconCidGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/cid-groups/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:post',Mandatory,Position=2)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function New-FalconUserGroup {
<#
.SYNOPSIS
Create a Falcon Flight Control user group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Name
User group name
.PARAMETER Description
User group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconUserGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/user-groups/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:post',Mandatory,Position=2)]
    [string]$Description
  )
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Remove-FalconCidGroup {
<#
.SYNOPSIS
Remove Falcon Flight Control CID groups
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
CID group
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCidGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/cid-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_ids','cid_group_id','ids')]
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
function Remove-FalconCidGroupMember {
<#
.SYNOPSIS
Remove members from a Falcon Flight Control CID group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
CID group identifier
.PARAMETER Cid
Customer identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconCidGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/cid-group-members/v2:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/cid-group-members/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/mssp/entities/cid-group-members/v2:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [Alias('cids','child_cid')]
    [string[]]$Cid
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Cid) {
      @($Cid).foreach{
        $Value = Confirm-CidValue $_
        if ($Value) { $List.Add($Value) }
      }
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['Cid'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconGroupRole {
<#
.SYNOPSIS
Remove roles between a Falcon Flight Control user group and CID group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER CidGroupId
CID group identifier
.PARAMETER UserGroupId
User group identifier
.PARAMETER RoleId
Role identifier, or leave blank to remove user group/CID group association
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconGroupRole
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/mssp-roles/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('cid_group_id')]
    [string]$CidGroupId,
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$UserGroupId,
    [Parameter(ParameterSetName='/mssp/entities/mssp-roles/v1:delete',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('role_ids','RoleIds')]
    [string[]]$RoleId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($RoleId) {
      @($RoleId).foreach{ $List.Add($_) }
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end {
    if ($List) {
      $PSBoundParameters['RoleId'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconUserGroup {
<#
.SYNOPSIS
Remove Falcon Flight Control user groups
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
User group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconUserGroup
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/user-groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_ids','user_group_id','ids')]
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
function Remove-FalconUserGroupMember {
<#
.SYNOPSIS
Remove members from a Falcon Flight Control user group
.DESCRIPTION
Requires 'Flight Control: Write'.
.PARAMETER Id
User group identifier
.PARAMETER UserId
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconUserGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/mssp/entities/user-group-members/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/mssp/entities/user-group-members/v1:delete',Mandatory,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('user_group_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/mssp/entities/user-group-members/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuids','uuid','UserIds')]
    [string[]]$UserId
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($UserId) { @($UserId).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['UserId'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
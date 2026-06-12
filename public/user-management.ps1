function Add-FalconProfileGroupMember {
<#
.SYNOPSIS
Add users to profile groups
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Uuid
User identifier
.PARAMETER Id
Profile group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconProfileGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/group-users-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/group-users-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','user_uuids')]
    [string[]]$Uuid,
    [Parameter(ParameterSetName='/user-management/entities/group-users-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','group_id','group_ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('action_parameters','filter','ids') }
        Query = @('action_name')
      }
    }
    [System.Collections.Generic.List[string]]$IdList = @()
    [System.Collections.Generic.List[PSCustomObject]]$ApList = @()
  }
  process {
    if ($Uuid) { @($Uuid).foreach{ $ApList.Add(([PSCustomObject]@{ name = 'user_uuid'; value = $_ })) }}
    if ($Id) { @($Id).foreach{ $IdList.Add($_ ) }}
  }
  end {
    if ($ApList -and $IdList) {
      $PSBoundParameters['action_name'] = 'add_users'
      $PSBoundParameters['Id'] = @($IdList)
      for ($i=0;$i -lt $ApList.Count;$i+=100) {
        # Submit in groups of 100 users
        $PSBoundParameters['action_parameters'] = @($ApList[$i..($i+99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Add-FalconRole {
<#
.SYNOPSIS
Assign roles to users
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER UserId
User identifier
.PARAMETER Cid
Customer identifier
.PARAMETER Id
User role
.PARAMETER ExpiresAt
Expiration date and time (UTC, RFC3339)
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Add-FalconRole
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/user-role-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('uuid','user_uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,Position=3)]
    [Alias('role_ids','ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Position=4)]
    [ValidatePattern('^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')]
    [Alias('expires_at','date','expiration')]
    [string]$ExpiresAt
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('action','cid','expires_at','role_ids','uuid') }}
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
      $PSBoundParameters['role_ids'] = @($List)
      $PSBoundParameters['uuid'] = $PSBoundParameters.UserId
      $PSBoundParameters['action'] = 'grant'
      [void]$PSBoundParameters.Remove('Id')
      [void]$PSBoundParameters.Remove('UserId')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Edit-FalconProfileGroup {
<#
.SYNOPSIS
Modify a profile group
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Id
Profile group identifier
.PARAMETER Name
Profile group name
.PARAMETER Description
Profile group description
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconProfileGroup
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/groups/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('group_id')]
    [string]$Id,
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Name,
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:patch',ValueFromPipelineByPropertyName,
      Position=3)]
    [string]$Description
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('description','name') }
        Query = @('id')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Edit-FalconUser {
<#
.SYNOPSIS
Modify the name of a user
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER FirstName
First name
.PARAMETER LastName
Last name
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Edit-FalconUser
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:patch',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Position=1)]
    [Alias('first_name')]
    [string]$FirstName,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Position=2)]
    [Alias('last_name')]
    [string]$LastName,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:patch',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('first_name','last_name') }
        Query = @('user_uuid')
      }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
function Get-FalconProfileGroup {
<#
.SYNOPSIS
Search for Falcon profile groups
.DESCRIPTION
Requires 'User management: Read'.
.PARAMETER Id
Profile group identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconProfileGroup
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/queries/groups/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/groups/GET/v1:post',ValueFromPipelineByPropertyName,
      ValueFromPipeline)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get',Position=2)]
    [ValidateSet('name|asc','name|desc','member_count|asc','member_count|desc','updated_at|asc','updated_at|desc')]
    [string]$Sort,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get')]
    [int32]$Offset,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/user-management/queries/groups/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('ids') }
        Query = @('filter','limit','offset','sort')
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      $Param['Max'] = 500
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
    
  }
}
function Get-FalconProfileGroupMember {
<#
.SYNOPSIS
List members of a profile group, or profile groups assigned to users
.DESCRIPTION
Requires 'User management: Read'.
.PARAMETER Id
Profile group identifier
.PARAMETER Uuid
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconProfileGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/group-users/GET/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/group-users/GET/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/entities/user-groups/GET/v1:post')]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [string[]]$Uuid
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('ids') } }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} elseif ($Uuid) { @($Uuid).foreach{ $List.Add($_) }}
  }
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Get-FalconRole {
<#
.SYNOPSIS
Search for user roles and assignments
.DESCRIPTION
Requires 'User management: Read'.
.PARAMETER Id
Role identifier
.PARAMETER UserId
User identifier
.PARAMETER Cid
Customer identifier
.PARAMETER DirectOnly
Display direct user role grants
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconRole
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/queries/roles/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/roles/GET/v2:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids','roles','role_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=1)]
    [Parameter(ParameterSetName='/user-management/entities/roles/GET/v2:post',Position=2)]
    [Parameter(ParameterSetName='/user-management/queries/roles/v1:get')]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=2)]
    [Alias('direct_only')]
    [boolean]$DirectOnly,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=3)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=4)]
    [ValidateSet('cid|asc','cid|desc','role_name|asc','role_name|desc','type|asc','type|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=5)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/user-management/queries/roles/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('ids') }
        Query = @('action','cid','direct_only','filter','limit','offset','sort','user_uuid')
      }
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) {
      @($Id).foreach{
        if ($_ -match '^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$') {
          Get-FalconRole -UserId $_
        } else {
          $List.Add($_)
        }
      }
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
function Get-FalconUser {
<#
.SYNOPSIS
Search for users
.DESCRIPTION
Requires 'User management: Read'.
.PARAMETER Id
User identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER Username
Username
.PARAMETER Include
Include additional properties
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconUser
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/queries/users/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/users/GET/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids','uuid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=2)]
    [ValidateSet('first_name|asc','first_name|desc','last_name|asc','last_name|desc','name|asc','name|desc',
      'uid|asc','uid|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get',Position=3)]
    [ValidateRange(1,500)]
    [int]$Limit,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='Username',Mandatory)]
    [ValidateScript({
      if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
    })]
    [Alias('uid','Usernames')]
    [string[]]$Username,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
    [Parameter(ParameterSetName='/user-management/entities/users/GET/v1:post')]
    [Parameter(ParameterSetName='Username')]
    [ValidateSet('roles',IgnoreCase=$false)]
    [string[]]$Include,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
    [Parameter(ParameterSetName='Username')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/user-management/queries/users/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('ids') }
        Query = @('filter','limit','offset','sort')
      }
      Max = 100
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($Username) {
      # Re-submit 'Username' values as filtered searches
      for ($i=0;$i -lt ($Username | Measure-Object).Count;$i+=100) {
        [string]$Filter = ($Username[$i..($i+99)] | ForEach-Object { "uid:*'$_'" }) -join ','
        if ($Filter) {
          $Search = @{ Filter = $Filter }
          if ($Include) { $Search['Include'] = $Include }
          if ($Detailed) { $Search['Detailed'] = $Detailed }
          & $MyInvocation.MyCommand.Name @Search
        }
      }
    } else {
      if ($IdList) { $PSBoundParameters['Id'] = @($List) }
      if ($Include) {
        $Request = Invoke-Falcon @Param -UserInput $PSBoundParameters
        if ($Request -and !$Request.uuid) { $Request = @($Request).foreach{ ,[PSCustomObject]@{ uuid = $_ }}}
        if ($Include -contains 'roles') {
          @($Request).foreach{ Set-Property $_ roles @(Get-FalconRole -UserId $_.uuid) }
        }
        $Request
      } else {
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Invoke-FalconProfileGroupAction {
<#
.SYNOPSIS
Perform actions on profile groups
.DESCRIPTION
Requires 'User management: Write'.

The values 'all_hosts', 'all_asset_groups', or 'all_access_scopes' can be used to assign or remove all
associated fine grained access objects to/from a profile group with the 'add_fga_objects' or
'remove_fga_objects' action.
.PARAMETER Name
Action to perform
.PARAMETER ActionParameter
PSCustomObject containing 'name' and 'value', including target CID
.PARAMETER Id
Profile group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconProfileGroupAction
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/group-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/group-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('add_roles','remove_roles','add_user_groups','remove_user_groups','add_fga_objects',
      'remove_fga_objects',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/user-management/entities/group-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [Alias('action_parameters')]
    [PSCustomObject[]]$ActionParameter,
    [Parameter(ParameterSetName='/user-management/entities/group-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValuefromPipeline,Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('action_parameters','filter','ids') }
        Query = @('action_name')
      }
    }
  }
  process {
    if ($PSBoundParameters.ActionParameter.Count -gt 100) {
      # Prevent more than 100 'action_parameters' values from being submitted at once
      throw "A maximum of 100 'action_parameters' can be submitted per request."
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Invoke-FalconUserAction {
<#
.SYNOPSIS
Perform an action on a user
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Name
Action name
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconUserAction
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/user-actions/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/user-actions/v1:post',Mandatory,Position=1)]
    [ValidateSet('reset_password','reset_2fa',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/user-management/entities/user-actions/v1:post',Mandatory,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('ids','action') }}
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Id'] = @($List)
      $PSBoundParameters['Action'] = @{ action_name = $PSBoundParameters.Name }
      [void]$PSBoundParameters.Remove('Name')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconProfileGroup {
<#
.SYNOPSIS
Create a profile group
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Name
Profile group name
.PARAMETER Description
Profile group description
.PARAMETER Cid
Destination CID, when creating a profile group in a Flight Control environment
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconProfileGroup
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/groups/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [string]$Description,
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('cid','description','name') } }
    }
  }
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function New-FalconUser {
<#
.SYNOPSIS
Create a user
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Username
Username
.PARAMETER Firstname
First name
.PARAMETER Lastname
Last name
.PARAMETER Password
Password. If left unspecified, the user will be emailed a link to set their password.
.PARAMETER Cid
Customer identifier
.PARAMETER ValidateOnly
Validate if user is allowed but do not create them
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconUser
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidateScript({
      if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
    })]
    [Alias('uid')]
    [string]$Username,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
      Position=2)]
    [Alias('first_name')]
    [string]$FirstName,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
      Position=3)]
    [Alias('last_name')]
    [string]$LastName,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
      Position=4)]
    [ValidatePattern('^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{12,}$')]
    [string]$Password,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
      Position=5)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/user-management/entities/users/v1:post',ValueFromPipelineByPropertyName,
      Position=6)]
    [Alias('validate_only')]
    [boolean]$ValidateOnly
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('cid','first_name','last_name','password','uid') }
        Query = @('validate_only')
      }
    }
  }
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Remove-FalconProfileGroup {
<#
.SYNOPSIS
Delete profile groups
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Id
Profile group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconProfileGroup
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/groups/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/groups/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','group_id','group_ids')]
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
function Remove-FalconProfileGroupMember {
<#
.SYNOPSIS
Remove users from profile groups
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Uuid
User identifier
.PARAMETER Id
Profile group identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconProfileGroupMember
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/group-users-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/group-users-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','user_uuids')]
    [string[]]$Uuid,
    [Parameter(ParameterSetName='/user-management/entities/group-users-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','group_id','group_ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{
        Body = @{ root = @('action_parameters','filter','ids') }
        Query = @('action_name')
      }
    }
    [System.Collections.Generic.List[string]]$IdList = @()
    [System.Collections.Generic.List[PSCustomObject]]$ApList = @()
  }
  process {
    if ($Uuid) { @($Uuid).foreach{ $ApList.Add(([PSCustomObject]@{ name = 'user_uuid'; value = $_ })) }}
    if ($Id) { @($Id).foreach{ $IdList.Add($_ ) }}
  }
  end {
    if ($ApList -and $IdList) {
      $PSBoundParameters['action_name'] = 'remove_users'
      $PSBoundParameters['Id'] = @($IdList)
      for ($i=0;$i -lt $ApList.Count;$i+=100) {
        # Submit in groups of 100 users
        $PSBoundParameters['action_parameters'] = @($ApList[$i..($i+99)])
        Invoke-Falcon @Param -UserInput $PSBoundParameters
      }
    }
  }
}
function Remove-FalconRole {
<#
.SYNOPSIS
Remove roles from a user
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER UserId
User identifier
.PARAMETER Cid
Customer identifier
.PARAMETER Id
User role
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconRole
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/user-role-actions/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('uuid','user_uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,
      ValueFromPipelineByPropertyName,Position=2)]
    [ValidatePattern('^[a-fA-F0-9]{32}(-\w{2})?$')]
    [string]$Cid,
    [Parameter(ParameterSetName='/user-management/entities/user-role-actions/v1:post',Mandatory,Position=3)]
    [Alias('role_ids','ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('action','cid','expires_at','role_ids','uuid') }}
    }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
      $PSBoundParameters['role_ids'] = @($List)
      $PSBoundParameters['uuid'] = $PSBoundParameters.UserId
      $PSBoundParameters['action'] = 'revoke'
      [void]$PSBoundParameters.Remove('Id')
      [void]$PSBoundParameters.Remove('UserId')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function Remove-FalconUser {
<#
.SYNOPSIS
Remove a user
.DESCRIPTION
Requires 'User management: Write'.
.PARAMETER Id
User identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconUser
#>
  [CmdletBinding(DefaultParameterSetName='/user-management/entities/users/v1:delete',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/user-management/entities/users/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$Id
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Query = @('user_uuid') }
    }
  }
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
@('Add-FalconRole','Get-FalconRole','Remove-FalconRole').foreach{
  Register-ArgumentCompleter -CommandName $_ -ParameterName 'Id' -ScriptBlock { Get-FalconRole -EA 0 }
}
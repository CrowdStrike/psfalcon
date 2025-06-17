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
Expiration date
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
    [ValidatePattern('^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T(00|[0-9]|1[0-9]|2[0-3]):([0-9]|[0-5][0-9]):([0-9]|[0-5][0-9])Z')]
    [Alias('expires_at','date','expiration')]
    [string]$ExpiresAt
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
      $PSBoundParameters['role_ids'] = @($List)
      $PSBoundParameters['uuid'] = $PSBoundParameters.UserId
      $PSBoundParameters['action'] = 'grant'
      $PSBoundParameters['expires_at'] = $PSBoundParameters.ExpiresAt
      [void]$PSBoundParameters.Remove('Id')
      [void]$PSBoundParameters.Remove('UserId')
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
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
    [Parameter(ParameterSetName='/user-management/entities/roles/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids','roles','role_id')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$')]
    [Alias('user_uuid','uuid')]
    [string]$UserId,
    [Parameter(ParameterSetName='/user-management/combined/user-roles/v2:get',Position=1)]
    [Parameter(ParameterSetName='/user-management/entities/roles/v1:get',Position=2)]
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 100 }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($Username) {
      # Re-submit 'Username' values as filtered searches
      for ($i = 0; $i -lt ($Username | Measure-Object).Count; $i += 100) {
        [string]$Filter = ($Username[$i..($i + 99)] | ForEach-Object { "uid:*'$_'" }) -join ','
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process {
    if ($PSBoundParameters.Cid) { $PSBoundParameters.Cid = Confirm-CidValue $PSBoundParameters.Cid }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
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
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
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
  begin { $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }}
  process { Invoke-Falcon @Param -UserInput $PSBoundParameters }
}
@('Add-FalconRole','Get-FalconRole','Remove-FalconRole').foreach{
  Register-ArgumentCompleter -CommandName $_ -ParameterName 'Id' -ScriptBlock { Get-FalconRole -EA 0 }
}

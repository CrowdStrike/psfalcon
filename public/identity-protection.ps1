function Invoke-FalconIdentityGraph {
<#
.SYNOPSIS
Interact with Falcon Identity using GraphQL
.DESCRIPTION
The 'All' parameter requires that your GraphQL statement contain an 'after' cursor variable definition and
'pageInfo { hasNextPage endCursor }'.

Requires 'Identity Protection GraphQL: Write', and other 'Identity Protection' permission(s) depending on query.
.PARAMETER String
A complete GraphQL statement
.PARAMETER Variable
A hashtable containing variables used in your GraphQL statement
.PARAMETER All
Repeat requests until all available results are retrieved
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconIdentityGraph
#>
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [Parameter(Mandatory,ValueFromPipeline,Position=1)]
    [Alias('query','mutation')]
    [string]$String,
    [Parameter(ValueFromPipeline,Position=2)]
    [Alias('variables')]
    [hashtable]$Variable,
    [switch]$All
  )
  begin {
    function Assert-CursorVariable ($UserInput,$EndCursor) {
      # Use variable definition to ensure 'Cursor' is within 'Variable' hashtable
      if ($UserInput.query -match '^(\s+)?query\s+?\(.+Cursor') {
        @([regex]::Matches($UserInput.query,
          '(?<=query\s+?\()(\$\w+:.[^\)]+)').Value -replace '\$',$null).foreach{
          $Array = ($_ -split ':',2).Trim()
          if ($Array[1] -eq 'Cursor') {
            if (!$UserInput.variables) {
              $UserInput.Add('variables',@{ $Array[0] = $EndCursor })
            } elseif ($UserInput.variables.($Array[0])) {
              $UserInput.variables.($Array[0]) = $EndCursor
            }
          }
        }
      }
      return $UserInput
    }
    function Invoke-GraphLoop ($Object,$Splat,$UserInput) {
      $RegEx = @{
        # Patterns to validate statement for 'pageInfo' and 'Cursor' variable
        CursorVariable = '^(\s+)?query\s+?\(.+Cursor'
        PageInfo = 'pageInfo(\s+)?{(\s+)?(hasNextPage([,\s]+)?|endCursor([,\s]+)?){2}(\s+)?}'
      }
      [string]$Message = if ($UserInput.query -notmatch $RegEx.CursorVariable) {
        "'-All' parameter was specified but 'Cursor' definition is missing from statement."
      } elseif ($UserInput.query -notmatch $RegEx.PageInfo) {
        "'-All' parameter was specified but 'pageInfo' is missing from statement."
      }
      if ($Message) {
        $PSCmdlet.WriteWarning(("[$($Splat.Command)]",$Message -join ' '))
      } else {
        do {
          if ($Object.entities.pageInfo.endCursor) {
            # Update 'Cursor' and repeat
            $UserInput = Assert-CursorVariable $UserInput $Object.entities.pageInfo.endCursor
            Write-GraphResult (Invoke-Falcon @Splat -UserInput $UserInput -OutVariable Object)
          }
        } while (
          $Object.entities.pageInfo.hasNextPage -eq $true -and $null -ne
            $Object.entities.pageInfo.endCursor
        )
      }
    }
    function Write-GraphResult ($Object) {
      if ($Object.entities.pageInfo) {
        # Output verbose 'pageInfo' detail
        [string]$Message = (@($Object.entities.pageInfo.PSObject.Properties).foreach{
          $_.Name,$_.Value -join '='
        }) -join ', '
        Write-Log 'Invoke-FalconIdentityGraph' ($Message -join ' ')
      }
      # Output 'nodes'
      if ($Object.entities.nodes) { $Object.entities.nodes } else { $Object }
    }
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = '/identity-protection/combined/graphql/v1:post'
      Format = @{ Body = @{ root = @('query','variables') }}
    }
  }
  process {
    if ($PSBoundParameters.All) {
      Write-GraphResult (Invoke-Falcon @Param -UserInput $PSBoundParameters -OutVariable Request)
    } else {
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
  end { if ($Request -and $PSBoundParameters.All) { Invoke-GraphLoop $Request $Param $PSBoundParameters }}
}
function Get-FalconIdentityHost {
<#
.SYNOPSIS
Search for Falcon Identity hosts
.DESCRIPTION
Requires 'Identity Protection Entities: Read'.
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
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIdentityHost
#>
  [CmdletBinding(DefaultParameterSetName='/identity-protection/queries/devices/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/identity-protection/entities/devices/GET/v1:post',
      ValueFromPipelineByPropertyName,ValueFromPipeline,Mandatory)]
    [ValidatePattern('^[a-fA-F0-9]{32}$')]
    [Alias('ids','device_id','host_ids','aid')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get',Position=1)]
    [ValidateScript({ Test-FqlStatement $_ })]
    [string]$Filter,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get',Position=2)]
    [string]$Sort,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get',Position=3)]
    [ValidateRange(1,200)]
    [int]$Limit,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get')]
    [int]$Offset,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/identity-protection/queries/devices/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $Param['Max'] = 5000
      $PSBoundParameters['Id'] = @($List)
    }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}
function Get-FalconIdentityRule {
<#
.SYNOPSIS
Search for Falcon Identity Protection policy rules
.DESCRIPTION
Requires 'Identity Protection Policy Rules: Read'.
.PARAMETER Id
Falcon Identity Protection policy rule identifier
.PARAMETER Name
Filter by rule name
.PARAMETER Enabled
Filter by rule enablement status
.PARAMETER SimulationMode
Filter by simulation mode
.PARAMETER Detailed
Retrieve detailed information
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconIdentityRule
#>
  [CmdletBinding(DefaultParameterSetName='/identity-protection/queries/policy-rules/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/identity-protection/queries/policy-rules/v1:get',Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/identity-protection/queries/policy-rules/v1:get',Position=2)]
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/identity-protection/queries/policy-rules/v1:get',Position=3)]
    [Alias('simulation_mode')]
    [boolean]$SimulationMode,
    [Parameter(ParameterSetName='/identity-protection/queries/policy-rules/v1:get')]
    [switch]$Detailed
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
      $Param['Max'] = 70
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}
function New-FalconIdentityRule {
<#
.SYNOPSIS
Create Falcon Identity Protection policy rules
.DESCRIPTION
Requires 'Identity Protection Policy Rules: Write'.
.PARAMETER Name
Rule name
.PARAMETER Action
Rule action
.PARAMETER Trigger
Rule trigger
.PARAMETER Enabled
Rule enablement status
.PARAMETER SimulationMode
Enable simulation mode
.PARAMETER Activity
Object containing 'accessType' and/or 'accessTypeCustom', for rule conditions based on access
.PARAMETER Destination
Object containing 'entityId' and/or 'groupMembership', for rule conditions based on destination
.PARAMETER SourceEndpoint
Object containing 'entityId' and/or 'groupMembership', for define rule conditions based on source endpoints
.PARAMETER SourceUser
Object containing 'entityId' and/or 'groupMembership', for define rule conditions based on source users
.LINK
https://github.com/crowdstrike/psfalcon/wiki/New-FalconIdentityRule
#>
  [CmdletBinding(DefaultParameterSetName='/identity-protection/entities/policy-rules/v1:post',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Mandatory,Position=1)]
    [string]$Name,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Mandatory,Position=2)]
    [ValidateSet('ADD_TO_WATCH_LIST','ALLOW','APPLY_SSO_POLICY','BLOCK','FORCE_PASSWORD_CHANGE','MFA',
      IgnoreCase=$false)]
    [string]$Action,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Mandatory,Position=3)]
    [ValidateSet('access','accountEvent','alert','federatedAccess',IgnoreCase=$false)]
    [string]$Trigger,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Mandatory,Position=4)]
    [boolean]$Enabled,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Mandatory,Position=5)]
    [boolean]$SimulationMode,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Position=6)]
    [object]$Activity,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Position=7)]
    [object]$Destination,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Position=8)]
    [object]$SourceEndpoint,
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:post',Position=9)]
    [object]$SourceUser
  )
  begin {
    $Param = @{
      Command = $MyInvocation.MyCommand.Name
      Endpoint = $PSCmdlet.ParameterSetName
      Format = @{ Body = @{ root = @('action','enabled','name','simulationMode','trigger','activity','destination',
        'sourceEndpoint','sourceUser') }}
    }
  }
  process {
    # Create 'JsonBody' for submission to ensure camelCase is used
    $JsonBody = @{}
    @($Param.Format.Body.root).foreach{
      if ($null -ne $PSBoundParameters.$_) { $JsonBody[$_] = $PSBoundParameters.$_ }
    }
    $Param['JsonBody'] = $JsonBody | ConvertTo-Json -Depth 32 -Compress
    Invoke-Falcon @Param
  }
}
function Remove-FalconIdentityRule {
<#
.SYNOPSIS
Remove Falcon Identity Protection policy rules
.DESCRIPTION
Requires 'Identity Protection Policy Rules: Write'.
.PARAMETER Id
Policy rule identifier
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Remove-FalconIdentityRule
#>
  [CmdletBinding(DefaultParameterSetName='/identity-protection/entities/policy-rules/v1:delete',
    SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/identity-protection/entities/policy-rules/v1:delete',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName; Max = 100 }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process { if ($Id) { @($Id).foreach{ $List.Add($_) }}}
  end {
    if ($List) { $PSBoundParameters['Id'] = @($List) }
    Invoke-Falcon @Param -UserInput $PSBoundParameters
  }
}


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
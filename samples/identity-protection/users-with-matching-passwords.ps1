#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
List user accounts with matching passwords
.DESCRIPTION
Use 'GroupId' to correlate the same passwords across users
.EXAMPLE
.\users-with-matching-passwords.ps1
.NOTES
Original script created by https://www.reddit.com/user/cobaltpsyche/
#>
param()
process {
  $RiskFactor = @('DUPLICATE_PASSWORD')
  $String = @'
query GetEntitiesByRiskFactor($after: Cursor, $riskFactors: [RiskFactorType!]) {
 entities(first: 1000, after: $after, riskFactorTypes: $riskFactors, sortKey: RISK_SCORE, sortOrder: DESCENDING) {
  edges {
   node {
    entityId, primaryDisplayName, secondaryDisplayName, type, riskScore, archived
    isAdmin: hasRole(type: AdminAccountRole)
    accounts { ... on ActiveDirectoryAccountDescriptor { passwordAttributes { lastChange }}}
    riskFactors {
     type, score, severity
     ... on AttackPathBasedRiskFactor {
      attackPath {
       relation
       entity { primaryDisplayName, type }
       nextEntity { primaryDisplayName, type }
      }
     }
     ... on DuplicatePasswordRiskEntityFactor { groupId }
    }
   }
  }
  pageInfo { hasNextPage, endCursor }
 }
}
'@
  Invoke-FalconIdentityGraph -String $String -Variable @{ riskFactors = $RiskFactor } -All | ForEach-Object {
    # For each entity that has a 'DUPLICATE_PASSWORD' risk, export selected fields
    @($_.entities.edges.node).Where({$_.riskFactors.type -eq 'DUPLICATE_PASSWORD'}).foreach{
      [PSCustomObject]($_ | Select-Object primaryDisplayName,secondaryDisplayName,isAdmin,archived,riskScore,type,
      @{
        l='groupId'
        e={@($_.riskFactors.groupId).Where({$null -ne $_})}
      },
      @{
        l='passwordLastSet'
        e={$_.accounts.passwordAttributes.lastChange}
      })
    } | Sort-Object -Property groupId
  }
}
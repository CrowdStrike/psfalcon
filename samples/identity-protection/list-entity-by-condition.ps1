#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
List entities matching a condition in Falcon Identity Protection
.PARAMETER Condition
Return results when this condition is true
.EXAMPLE
.\list-entity-by-condition.ps1 -Condition accountLocked
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidateSet('accountLocked','cloudEnabled','cloudOnly','hasAgedPassword','hasAgent','hasExposedPassword',
    'hasNeverExpiringPassword','hasOpenIncidents','hasVulnerableOs','hasWeakPassword','inactive','learned',
    'marked','shared','stale','unmanaged','watched',IgnoreCase=$false)]
  [string]$Condition
)
process {
  $String = 'query($after:Cursor){entities(' + $Condition + ':true,archived:false,first:1000,after:$after){nodes' +
    '{primaryDisplayName,secondaryDisplayName,isHuman:hasRole(type:HumanUserAccountRole),isProgrammatic:hasRole(' +
    'type:ProgrammaticUserAccountRole),riskScore,riskScoreSeverity}pageInfo{hasNextPage,endCursor}}}'
  try {
    Invoke-FalconIdentityGraph -String $String -All
  } catch {
    throw $_
  }
}
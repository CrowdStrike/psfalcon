#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Add a host group to all Sensor Visibility Exclusions
.PARAMETER GroupId
Group identifier
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$GroupId
)
Get-FalconSvExclusion -Detailed -All | ForEach-Object {
  Edit-FalconSvExclusion -Id $_.id -GroupId @($_.groups.id,$GroupId)
}
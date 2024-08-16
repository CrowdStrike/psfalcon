#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Perform a pre-defined Event Search for a target device using a Fusion workflow
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.EXAMPLE
.\dev05_lab01_direct_rtr.ps1 -ClientId abc -ClientSecret def -String "Hello World!"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret
)
process {
  try {
    Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret
    $Json = Get-FalconHost -Filter "hostname:'SE-BKR-WIN11'" -Sort 'last_seen.desc' -Limit 1 -Verbose |
      Select-Object @{l='device_id';e={$_}},@{l='search';e={$true}} | ConvertTo-Json -Compress
    if (!$Json) { throw "Failed to create Json for workflow submission." }
    $Execution = Invoke-FalconWorkflow -Name dev05_workflow -Json $Json -Verbose
    if ($Execution) { Write-Host "Started Fusion workflow 'dev05_workflow'. [$Execution]" }
  } catch {
    throw $_
  }
}
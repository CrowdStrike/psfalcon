#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Pass a string to Write-Output on a remote host using a Fusion Workflow
.DESCRIPTION
NGSIEM event search:
event_type=FusionWorkflowEvent device_id=* result=*
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER String
Desired string to send to Write-Output on the target host
.EXAMPLE
.\dev05_lab02_workflow_rtr.ps1 -ClientId abc -ClientSecret def -String "Hello World!"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$ClientId,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^\w{40}$')]
  [string]$ClientSecret,
  [Parameter(Mandatory,Position=3)]
  [string]$String
)
process {
  try {
    Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret
    $Json = Get-FalconHost -Filter "hostname:'SE-BKR-WIN11'" -Sort 'last_seen.desc' -Limit 1 -Detailed -Verbose |
      Select-Object device_id,platform_name,@{l='echo';e={$String}} | ConvertTo-Json -Compress
    if (!$Json) { throw "Failed to create Json for workflow submission." }
    $Execution = Invoke-FalconWorkflow -Name dev05_workflow -Json $Json -Verbose
    if ($Execution) { Write-Host "Started Fusion workflow 'dev05_workflow'. [$Execution]" }
  } catch {
    throw $_
  }
}
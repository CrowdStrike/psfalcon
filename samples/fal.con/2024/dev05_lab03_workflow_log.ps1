#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Pass a string to NGSIEM
.DESCRIPTION
NGSIEM event search:
event_type=FusionWorkflowEvent echo=*
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER String
Desired string to send to NGSIEM
.EXAMPLE
.\dev05_lab03_workflow_log.ps1 -ClientId abc -ClientSecret def -String "Hello World!"
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
    $Json = @{ echo = $String; direct_log = $true } | ConvertTo-Json -Compress
    if (!$Json) { throw "Failed to create Json for workflow submission." }
    $Execution = Invoke-FalconWorkflow -Name dev05_workflow -Json $Json -Verbose
    if ($Execution) { Write-Host "Started Fusion workflow 'dev05_workflow'. [$Execution]" }
  } catch {
    throw $_
  }
}
#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion='2.2'}
<#
.SYNOPSIS
Pass a string to Write-Output on a remote host using Real-time Response
.PARAMETER ClientId
API client identifier
.PARAMETER ClientSecret
API client secret
.PARAMETER String
Desired string to send to Write-Output on the target host
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
  [string]$ClientSecret,
  [Parameter(Mandatory,Position=3)]
  [string]$String
)
process {
  try {
    Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret
    $DeviceId = Get-FalconHost -Filter "hostname:'SE-BKR-WIN11'" -Sort 'last_seen.desc' -Limit 1 -Verbose
    if (!$DeviceId) { throw "Failed to retrieve target device_id." }
    $Splat = @{
      Command = 'runscript'
      Argument = "-CloudFile='dev05_rtr_echo_script' -CommandLine='$String'"
      HostId = $DeviceId
      Verbose = $true
    }
    Invoke-FalconRtr @Splat
  } catch {
    throw $_
  }
}
#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Download the installer packaged assigned to a specific Sensor Update policy
.PARAMETER PolicyId
Sensor update policy identifier
#>
param(
  [Parameter(Mandatory)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$PolicyId
)
try {
  # Retrieve Sensor Update policy detail
  $Policy = Get-FalconSensorUpdatePolicy -Id $PolicyId
  if ($Policy.platform_name -and $Policy.settings) {
    # Use build and sensor_version to create regex pattern
    [regex]$Pattern = "^($([regex]::Escape(
      ($Policy.settings.sensor_version -replace '\.\d+$',$null)))\.\d{1,}|\d\.\d{1,}\.$(
      $Policy.settings.build.Split('|')[0]))$"
    $Match = try {
      # Select matching installer from list for 'platform_name' using regex pattern
      Get-FalconInstaller -Filter "platform:'$($Policy.platform_name.ToLower())'" -Detailed |
        Where-Object { $_.version -match $Pattern -and $_.description -match 'Falcon Sensor' }
    } catch {
      throw 'Unable to find installer through version match'
    }
    if ($Match.sha256 -and $Match.name) {
      $Installer = Join-Path -Path (Get-Location).Path -ChildPath $Match.name
      if ((Test-Path $Installer) -and ((Get-FileHash -Algorithm SHA256 -Path $Installer) -eq
      $Match.sha256)) {
        # Abort if matching file already exists
        throw "File exists with matching hash [$($Match.sha256)]"
      } elseif (Test-Path $Installer) {
        # Remove other versions
        Remove-Item -Path $Installer -Force
      }
      # Download the installer package
      Receive-FalconInstaller -Id $Match.sha256 -Path $Installer
    } else {
      throw "Properties 'sha256' or 'name' missing from installer result"
    }
  }
} catch {
  throw $_
}
#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Import a list of hostnames from CSV and network contain matching devices
.PARAMETER Path
Path to the CSV file containing a list of hostnames
.NOTES
This example requires a CSV with a column labeled 'hostname'. It will create a new CSV with that includes
'hostname', 'device_id' and 'contain_requested' status in the current directory.
#>
param(
  [Parameter(Mandatory)]
  [ValidatePattern('\.csv$')]
  [string]$Path
)
# Create output file CSV name and import values from CSV
[string]$OutputFile = Join-Path (Get-Location).Path "contained_$(Get-Date -Format FileDateTime).csv"
$Import = Import-Csv -Path $Path
if (!$Import.hostname) { throw "No 'hostname' column found in '$Path'." }

# Search for hosts and capture the most recently seen result that matches the provided hostname
[System.Collections.Generic.List[object]]$HostList = @()
@($Import.hostname).Where({![string]::IsNullOrEmpty($_)}).foreach{
  @(Get-FalconHost -Filter "hostname:['$_']" -Limit 1 -Sort last_seen.desc -Detailed | Select-Object device_id,
  hostname).foreach{
    $HostList.Add($_)
  }
}
if (!$HostList.hostname) {
  # Error if no matches were found
  throw "No hosts found."
} else {
  # Contain devices
  $HostList.device_id | Invoke-FalconHostAction -Name contain -OutVariable ContainList
  @($HostList).foreach{
    # Add 'contain_requested' property and export to CSV
    $Status = if ($ContainList.id -contains $_.device_id) { $true } else { $false }
    $_.PSObject.Properties.Add((New-Object PSNoteProperty('contain_requested',$Status)))
  }
  $HostList | Export-Csv -Path $OutputFile -NoTypeInformation
  if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
}
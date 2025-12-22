#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Create Device Control policy exceptions using a CSV with 'Device ID' (a.k.a. combined_id) values
.PARAMETER CsvPath
Path to CSV file containing 'Device ID' column
.PARAMETER PolicyId
Device Control policy identifier
.PARAMETER Class
USB device class to create exceptions under [default: 'MASS_STORAGE']
.PARAMETER Action
Action for created exception(s) [default: 'FULL_ACCESS']
.PARAMETER Expiration
Expiration time for created exception(s)
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory,Position=1)]
  [ValidateScript({
    if (!(Test-Path $_)) {
      throw ('"{0}" not found.' -f $_)
    } elseif (($_ | Split-Path -Leaf) -notmatch '.csv$') {
      throw 'Only CSV files are accepted.'
    } else {
      $true
    }
  })]
  [string]$CsvPath,
  [Parameter(Mandatory,Position=2)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$PolicyId,
  [Parameter(Position=3)]
  [ValidateSet('ANY','AUDIO_VIDEO','IMAGING','MASS_STORAGE','MOBILE','PRINTER','WIRELESS',
    'REMOVABLE_STORAGE_SDCARD',IgnoreCase=$false)]
  [string]$Class,
  [Parameter(Position=4)]
  [ValidateSet('BLOCK_ALL','BLOCK_EXECUTE','BLOCK_WRITE_EXECUTE','FULL_ACCESS',IgnoreCase=$false)]
  [string]$Action,
  [Parameter(Position=5)]
  [string]$Expiration
)
begin {
  # Set default 'Class' and 'Action'
  if (!$Class) { $Class = 'MASS_STORAGE' }
  if (!$Action) { $Action = 'FULL_ACCESS' }
}
process {
  [System.Collections.Generic.List[PSCustomObject]]$Csv = try {
    # Import CSV
    Import-Csv $CsvPath
  } catch {
    throw $_
  }
  [System.Collections.Generic.List[PSCustomObject]]$IdList = if (!$Csv.'Device ID') {
    # Error if 'Device ID' column is not present in CSV
    throw ('"Device ID" column not present in "{0}"!' -f $CsvPath)
  } else {
    # Create exception object(s) from unique 'Device ID' values
    @($Csv.'Device ID' | Select-Object -Unique).foreach{
      [PSCustomObject]($_ | Select-Object @{l='action';e={$Action}},@{l='class';e={$Class}},
        @{l='combined_id';e={$_}},@{l='expiration_time';e={if ($Expiration) { $Expiration } else { $null }}})
    }
  }
  Write-Host ('Found {0} unique combined_id(s) [{1} total]' -f $IdList.Count,$Csv.'Device ID'.Count)
  if ($IdList) {
    try {
      Edit-FalconDeviceControlClass -Id $PolicyId -UsbClass @{ upsert_exceptions = $IdList }
    } catch {
      throw $_
    }
  }
}
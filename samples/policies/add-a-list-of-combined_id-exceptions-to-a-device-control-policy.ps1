#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Add a list of 'combined_id' values to an existing Device Control policy
.PARAMETER PolicyId
Device Control policy identifier
.PARAMETER CombinedId
One or more 'combined_id' values to add to the target policy
.NOTES
This script will create 'FULL_ACCESS' exceptions for the 'MASS_STORAGE' class within an existing policy. You can
modify the hashtable created in '$Exception' to add key/value pairs like 'vendor_name' or 'product_name'.
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidatePattern('^[a-fA-F0-9]{32}$')]
  [string]$PolicyId,
  [Parameter(Mandatory,Position=2)]
  [string[]]$CombinedId
)
# Maximum number of exceptions to add per request
$Max = 50
for ($i=0; $i -lt ($CombinedId | Measure-Object).Count; $i+=$Max) {
  # Create exceptions in groups of $Max
  [string[]]$IdGroup = $CombinedId[$i..($i + ($Max - 1))]
  [object[]]$Exception = @($IdGroup).foreach{ @{ action = 'FULL_ACCESS'; combined_id = $_ }}
  $Setting = [PSCustomObject]@{ classes = @(@{ id = 'MASS_STORAGE'; exceptions = $Exception })}
  @(Edit-FalconDeviceControlPolicy -Id $PolicyId -Setting $Setting).foreach{
    # Validate presence of 'combined_id' in policy
    [object[]]$Created = ($_.settings.classes | Where-Object { $_.id -eq 'MASS_STORAGE' }).exceptions
    @($IdGroup).foreach{ if ($Created.combined_id -contains $_) { Write-Output "Added: $_" }}
  }
}
#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
**WARNING**: `Find-FalconDuplicate` only determines whether or not a device is a "duplicate" by hostname in this
example. There may be a legitimate reason that two devices have the same hostname in your environment. It is your
responsibility to determine whether or not the hosts reported by `Find-FalconDuplicate` are correct. This script
does not provide you with an opportunity to review those hosts before they are hidden, but it does output a list
after the hiding is complete. If devices are hidden incorrectly they will continue to communicate with Falcon
and can be restored from the trash using their `aid` value and `Invoke-FalconHostAction`.
#>
param(
    [switch]$Confirm
)
[string]$OutputFile = Join-Path (Get-Location).Path "duplicates_$(Get-Date -Format FileDateTime).csv"

# Use Find-FalconDuplicate to find duplicate hosts and hide them
Find-FalconDuplicate -OutVariable Duplicate | Invoke-FalconHostAction -Name hide_host
if ($Duplicate) {
    # If duplicates were found, output to CSV and display file
    $Duplicate | Export-Csv -Path $OutputFile -NoTypeInformation
    if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
}
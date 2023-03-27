#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Import a list of devices from CSV and contain them
.PARAMETER Path
Path to the CSV file containing a list of devices
.NOTES
This example requires a CSV with a column labeled 'hostname'. It will create a new CSV with that includes
'hostname', 'device_id' and 'contain_requested' status.
#>
param(
    [Parameter(Mandatory)]
    [ValidatePattern('\.csv$')]
    [string]$Path
)
[string]$OutputFile = Join-Path (Get-Location).Path "contained_$(Get-Date -Format FileDateTime).csv"
$Import = Import-Csv -Path $Path
if (!$Import.hostname) { throw "No 'hostname' column found in '$Path'." }

# Use Find-FalconDuplicate to find duplicate hosts and contain them
$Import.hostname | Find-FalconHostname -OutVariable HostList |
    Invoke-FalconHostAction -Name contain -OutVariable ContainList
if (!$HostList.hostname) {
    # Error if no matches were found
    throw "No hosts found."
} else {
    @($HostList).foreach{
        # Add 'contain_requested' property and export to CSV
        $Status = if ($ContainList.id -contains $_.device_id) { $true } else { $false }
        $_.PSObject.Properties.Add((New-Object PSNoteProperty('contain_requested',$Status)))
    }
    $HostList | Export-Csv -Path $OutputFile -NoTypeInformation
    if (Test-Path $OutputFile) { Get-ChildItem $OutputFile | Select-Object FullName,Length,LastWriteTime }
}
#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Find a host matching a given hostname and contain it
.PARAMETER Hostname
Hostname for the target device, identical to how it is listed in the Falcon console
#>
param(
    [Parameter(Mandatory)]
    [string]$Hostname
)
# Get identifier for target system and choose the most recently seen (in case of duplicates)
Get-FalconHost -Filter "hostname:['$Hostname']" -Sort last_seen.desc -Limit 1 -OutVariable Target |
    Invoke-FalconHostAction -Name contain
if (!$Target) { throw "No identifier found for '$Hostname'." }